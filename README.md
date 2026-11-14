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
- grant は scope（`op://Vault/Item/field` の完全一致 allowlist）・TTL・
  読取回数上限つき。read-only。監査ログ（ref と結果のみ、秘密の値は残さ
  ない）もメモリ内。

## 構成

- サーバー: muse-agent コンテナ（systemd `op-broker.service`、
  `/opt/op-broker/opbroker serve --listen :18787 --op /usr/bin/op`）
  - 到達経路: Tailscale `http://100.74.95.119:18787` / 自宅 infra
    `http://10.24.0.31:18787`。インターネットには出していない。
  - Admin token は起動ごとに生成され journal に一度だけ出る:
    `journalctl -u op-broker | grep "ADMIN TOKEN"`
  - op CLI は公式 apt リポジトリから導入済み（2.42.0）。
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
export BROKER_SERVER=http://100.74.95.119:18787
eval $(opbroker request --name macbook-pro --reason "作業名" \
        op://Automation/demo/password)
# 表示される6桁コードをダッシュボードで照合して承認すると進む
opbroker read op://Automation/demo/password
opbroker status
```

## 状態と既知の割り切り

- v1 は平文 HTTP（Tailscale / WireGuard / 自宅 LAN の暗号化と信頼に依存）。
  公開が必要になったら oauth2-proxy + Pocket ID を前段に置く。
- サーバー再起動 = 全ロック。再 unlock と再承認が必要（仕様）。
- バックエンドが人間アカウントの手動セッションではなく Service Account
  前提なのは、`op` のセッション鍵がディスク保存される設計と「メモリのみ」
  が衝突するため。
