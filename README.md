# op-broker

承認ゲート付きの secrets broker。1Password の秘密を「常に読める」状態にせず、
オーナーの Web 承認がある間だけ、承認されたクライアントにだけ読ませる。

## 設計

- **サーバーは資格情報をディスクに保存しない。** 1Password Service Account
  token はオーナーが Web ダッシュボードから登録（unlock）し、プロセスの
  メモリにだけ保持する。再起動すると locked に戻り、全 grant も消える。
- **クライアントの鍵は plain なチケットで十分**という割り切り。認証の本体は
  オーナーの Web 承認であり、チケットは「承認したリクエストとその後の
  読み取りを紐付ける claim ticket」でしかない。チケットはシェルの環境変数
  (`BROKER_TICKET`) にだけ持ち、Keychain 等には置かない。
- **申請の真贋は6桁コードの目視照合で担保する。** クライアントが表示する
  コードとダッシュボードのコードが一致することを確認してから承認する
  （OAuth device flow と同じ型）。
- grant は scope（下記のパターン allowlist）・TTL・
  読取回数上限つき。read-only。監査ログ（ref と結果のみ、秘密の値は残さ
  ない）もメモリ内。

## 構成

- サーバー: talos-baremetal クラスタに GitOps でデプロイ
  （k8s-manifests `apps/op-broker/`、ns `op-broker`）。Pod は
  initContainer でこの repo のリリースバイナリと公式 op CLI を
  SHA-256 検証つきで取得して起動する（クラスタに private registry が
  ないための altkeeper と同じパターン）。状態は Pod のメモリのみで、
  PVC は使わない。
  - 到達経路: **`https://op.tsuzu.dev`**（Cloudflare の DNS-only A
    レコード → LoadBalancer 10.24.0.202:443、infra net のみで
    インターネットには出していない）。broker 自身が TLS を終端する
  - 証明書は cert-manager の Let's Encrypt 証明書（DNS-01 検証）。
    プライベート IP を指す名前でも公開信頼の証明書が取れるのが要点
  - ダッシュボードは **Pocket ID ゲート**（oauth2-proxy サイドカー、
    passkey ログイン）の内側。サイドカーが TLS 終端と認証を担い、
    broker へは loopback でユーザーヘッダーを渡す（broker は loopback
    からのヘッダーだけを信頼する）。クライアント API（`/api/`）は
    ゲート対象外で、従来どおりチケット認証のみ
  - Admin token ログインも残してある（フォールバック）。トークンは
    Pod 起動ごとに生成され Pod ログに一度だけ出る:
    `kubectl -n op-broker logs deploy/op-broker | grep "ADMIN TOKEN"`
- クライアント: 同一バイナリ。Mac は `~/.local/bin/opbroker`
  (darwin/arm64 ビルド)。

## 使い方

初回（オーナー作業）:

1. 1Password に専用 vault（例 `Automation`）を作り、機械に読ませたい
   アイテムだけを移す／作る。個人のメイン SSH 鍵などは移さない。
2. Service Account を発行し、その vault の read のみ許可する。
3. ダッシュボードを開き、Admin token でログイン → SA token を貼って
   Unlock。

クライアント（Mac）:

```sh
export BROKER_SERVER=https://op.tsuzu.dev
eval $(opbroker request --name macbook-pro --reason "作業名" \
        op://Automation/demo/password)
# 表示される6桁コードをダッシュボードで照合して承認すると進む
opbroker read op://Automation/demo/password
opbroker status
```

エージェント方式（推奨、特に Codex 等のツールから使う場合）:
`request --agent` は承認されたチケットをローカルエージェント
（ssh-agent と同じ発想の常駐プロセス）のメモリに預ける。以後の
`read` / `status` は環境変数なしで動き、チケット文字列がシェル・
ツール・コマンドラインに一切現れない。エージェントは grant の期限で
チケットを破棄し、保持チケットが無い状態が10分続くと終了する。

```sh
opbroker request --agent --name codex --reason "作業名" op://Automation
# 6桁コードをダッシュボードで承認するだけ
opbroker read op://Automation/demo/password   # env 不要
opbroker agent --list     # 保持中の grant（メタデータのみ）
opbroker agent --forget   # 手動でチケットを捨てる
opbroker agent --stop     # エージェント終了
```

`$BROKER_TICKET` が設定されていればそちらが優先される。

エージェントは **複数の grant を同時に保持できる**。別の scope で
`request --agent` しても既存のチケットは消えず、`read` / `describe`
は参照をカバーする grant のチケットを自動で選ぶ。`status` は保持中の
全 grant を表示する。

また `request --agent` は、保持中の grant が要求 scope をカバーし
残り時間が **30分以上** ある場合、新規リクエストを作らずにそのまま
正常終了する（スクリプトが同じリクエストを繰り返し飛ばしても、
ダッシュボードやプッシュ通知は騒がない）。閾値は
`--min-remaining 1h` のように変更でき、`0s` で無効化できる。

### 更新（renew）

grant の期限が切れた（または切れそうな）ときは、新規リクエストでは
なく更新ができる。チケットは同じものが使われ続け、エージェントの
預かりもそのまま。承認は新規リクエストとまったく同じ（ダッシュ
ボード＋プッシュ通知）。失効から24時間を過ぎた grant は更新できない。

```sh
opbroker renew                 # エージェント保持が1件ならそれを更新
opbroker renew op://milldea    # カバーする grant を指定して更新
opbroker renew --ttl 2h        # 延長幅の希望（最終決定は承認時）
```

### プッシュ通知先の永続化（任意）

既定では通知先（FCM デバイストークン）もメモリのみで、再起動で
消える（ダッシュボードを開くと再登録される）。`--push-token-s3`
を指定すると **トークンだけ** を S3 上の小さな JSON に同期し、
再起動をまたいで保持する。認証は Web Identity（Pod の projected
SA トークン→ STS で一時認証情報に交換）で、静的な鍵は置かない。
SA トークン・grant・監査ログは従来通りメモリのみ。

```sh
opbroker serve --push-token-s3 http://10.24.0.138:8333/op-broker/push-tokens.json
```

### SSH 鍵を ssh-agent へ（ssh-add）

1Password 内の SSH 鍵も、同じ承認モデルのままローカルの ssh-agent
で使える。秘密鍵は broker 経由で OpenSSH 形式のまま取得され、
`ssh-add` の標準入力に渡るだけで、ディスクには書かれず表示も
されない。agent 側の有効期間はデフォルトで grant の残り時間に
一致する（`--lifetime` で変更可）。

```sh
opbroker request --agent op://MyVault        # 未承認なら先に承認
opbroker describe op://MyVault/my-server     # 鍵フィールドの参照を確認
opbroker ssh-add "op://MyVault/my-server/private key"
ssh-add -l                                   # 投入されたことを確認
```

対象アイテムは Service Account から見えるボールトに置くこと
（鍵フィールドの参照はアイテムにより異なるので describe で確認）。

### スコープの後追加（オーナー操作）

ダッシュボードの有効な grant 一覧から、各 grant にスコープ参照を
後から追加できる（監査ログに `scope-added` として記録）。範囲外の
参照で `denied-scope` になったクライアントを、再リクエストなしに
救済するためのオーナー操作。

フィールド参照の探索（describe）:
アイテムのフィールド名（特に TOTP のラベル）が分からないときは、
`opbroker describe op://Vault/Item` でフィールド構成だけを取得できる。
返るのはセクション名・ラベル・型と読み取り用参照のみで、値や TOTP の
seed は含まれない。read と同じ grant / scope で認可され、read 枠を
1つ消費する。OTP フィールドには現在コード用の参照
（`...?attribute=otp`）も併記される。

```sh
opbroker describe op://milldea/"SMMR stg"
opbroker read "op://milldea/SMMR stg/<ラベル>?attribute=otp"
```

scope は階層パターンで指定できる（承認した範囲内なら何度でも読める。
TTL と read 回数上限は従来どおり効く）:

| scope | 読める範囲 |
|---|---|
| `op://Vault/Item/field` | そのフィールドだけ |
| `op://Vault/Item` | そのアイテムの全フィールド |
| `op://Vault` / `op://Vault/*` | その vault の全アイテム |
| `op://*` | SA トークンが見える全部 |

実際の上限は Service Account の vault 権限。広い scope を承認すると
その分だけクライアントの権限が広がるので、理由と TTL は絞ること。

## PWA とプッシュ通知（Firebase）

ダッシュボードは PWA としてホーム画面に追加でき、新しい申請が来たら
Firebase Cloud Messaging 経由で Web Push が届く（iPhone は iOS 16.4+
でホーム画面に追加したアプリからのみ通知可）。

有効化には serve へ2つのファイルを渡す:

```
opbroker serve --firebase-config firebase-config.json \
               --fcm-credentials service-account.json ...
```

- `firebase-config.json`: Web アプリ設定（apiKey / authDomain /
  projectId / storageBucket / messagingSenderId / appId）に Web Push
  証明書の公開鍵 `vapidKey` を加えたもの。公開識別子のみで秘密はない。
- `service-account.json`: FCM HTTP v1 送信用の Google サービス
  アカウント鍵。サーバーは stdlib だけで RS256 JWT → OAuth2 トークン
  交換 → messages:send を行う。

挙動:

- 通知はデータのみで送り、Service Worker が組み立てる。タイトル・
  本文にクライアント名・ホスト・scope・理由を含み、**6桁の確認
  コードはロック画面に漏らさないため含めない**（照合はアプリ内で）。
- デバイストークンはメモリ内のみ。再起動で消えるが、ダッシュボード
  を開くたび自動で再登録される。
- FCM が UNREGISTERED を返したトークンは自動で掃除する。

## 状態と既知の割り切り

- ダッシュボードは Pocket ID ゲートの内側（上記）。インターネットには
  出していない（infra net 内のみ）。
- サーバー再起動 = 全ロック。再 unlock と再承認が必要（仕様）。
- バックエンドが人間アカウントの手動セッションではなく Service Account
  前提なのは、`op` のセッション鍵がディスク保存される設計と「メモリのみ」
  が衝突するため。
