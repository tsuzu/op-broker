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
opbroker agent --forget   # 手動でチケットを捨てる
opbroker agent --stop     # エージェント終了
```

`$BROKER_TICKET` が設定されていればそちらが優先される。

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

## 状態と既知の割り切り

- ダッシュボードは Pocket ID ゲートの内側（上記）。インターネットには
  出していない（infra net 内のみ）。
- サーバー再起動 = 全ロック。再 unlock と再承認が必要（仕様）。
- バックエンドが人間アカウントの手動セッションではなく Service Account
  前提なのは、`op` のセッション鍵がディスク保存される設計と「メモリのみ」
  が衝突するため。
