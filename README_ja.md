# Secure Shell Server

LLM（大規模言語モデル）が危険なシェルコマンドを実行するのを防ぐために設計された、Go ベースの MCP（Model Context Protocol）サーバーです。許可リストに基づいてすべてのコマンドを検証し、明示的に許可された操作のみに制限するサンドボックス環境を提供します。

## セキュリティに関する重要事項

本サーバーは複数のセキュリティ対策を実装していますが、すべての悪意あるコマンドや高度な攻撃に対する完全な保護を保証するものではありません。以下の点にご注意ください：

- 許可リストは必要なコマンドのみを含むよう慎重に設定してください
- 不審な操作がないか定期的にログを確認してください
- 包括的なセキュリティ戦略の一層として使用してください
- 高セキュリティ環境ではこのツールだけに依存しないでください

## 機能

- **コマンド許可リスト**: ユーザーが提供するシェルスクリプトを解析し、許可されたコマンドのみが使用されていることを検証します。
- **安全な実行**: カスタムランナーを使用してコマンド実行時に許可リストを強制します。
- **サブコマンド検証**: 再帰的なサブコマンドルールにより、許可されたサブコマンドをきめ細かく制御できます。
- **フラグ拒否**: 任意のネスト階層でコマンドやサブコマンドの危険なフラグをブロックします（例：`git push --force` の防止）。
- **ディレクトリ制限**: ファイルシステムアクセスを明示的に許可されたディレクトリのみに制限します。
- **パス検証**: すべてのパス引数を検証し、許可されていないディレクトリへのアクセスを防止します。
- **タイムアウト制御**: リソース枯渇を防ぐため、長時間実行されるコマンドを自動的に終了します。
- **詳細なログ**: 監査とデバッグのため、すべてのコマンド試行と実行結果をログに記録します。
- **MCP サーバーモード**: 安全なコマンド実行のための Model Context Protocol (MCP) サーバーとして機能します。

## インストール

```bash
go get /path/to/secure-shell-server
cd /path/to/secure-shell-server
make build
```

バイナリは `bin/` ディレクトリに生成されます。

## 使い方

### MCP サーバーの起動

```bash
./bin/server -config=/path/to/config.json
```

### server のコマンドラインオプション

- `-config`: 設定ファイルのパス
- `-stdio`: MCP 通信に stdin/stdout を使用
- `-port`: リッスンポート（デフォルト: 8080、stdio 不使用時）

## Claude Desktop のセットアップ

Claude Desktop で secure-shell-server を使用するには：

1. Claude Desktop の設定ファイルを編集します：
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
2. `tools` セクションに以下を追加します：

```json
"shell": {
  "command": "/path/to/secure-shell-server/bin/server",
  "args": [
    "-config",
    "~/path/to/your/config.json"
  ]
}
```

3. 任意の場所（macOS では `~/.mcp_shell_config.json` など）に設定ファイルを作成します
4. Claude Desktop を再起動して変更を適用します

## MCP ツール

サーバーは 2 つの MCP ツールを公開します：

### `run`

現在の作業ディレクトリでシェルコマンドを実行します。許可されたコマンドのみ実行可能です。`cd` コマンドでディレクトリを変更できます（`allowedDirectories` 内のみ）。`cd` によるディレクトリ変更は後続の `run` 呼び出しに引き継がれます。

| パラメータ | 必須 | 説明 |
|-----------|------|------|
| `commands` | はい | 実行するコマンドのリスト。`cd` で許可されたパス内のディレクトリに移動できます。 |
| `mode` | いいえ | `"parallel"`（デフォルト）または `"serial"` |

### `pwd`

現在の作業ディレクトリを表示します。

### 使用フロー

```
1. run(commands: ["cd /home/user/project"])             -> 作業ディレクトリを設定
2. run(commands: ["ls -la"])                            -> コマンド実行
3. run(commands: ["echo hello"])                        -> ディレクトリは維持される
4. pwd()                                               -> 現在のディレクトリを確認
5. run(commands: ["cd /tmp"])                           -> ディレクトリ変更
6. run(commands: ["pwd"])                               -> /tmp で実行
7. run(commands: ["cd subdir", "ls -la"], mode: "serial") -> cd + コマンドを1回の呼び出しで
```

## 設定

セキュリティポリシーは JSON 設定ファイルで定義します。ここでは主要な設定オプション、特にサブコマンドとフラグ拒否機能について説明します。

### 基本構造

```json
{
  "allowedDirectories": ["/home", "/tmp"],
  "allowCommands": [...],
  "denyCommands": [...],
  "defaultErrorMessage": "Command not allowed",
  "maxExecutionTime": 120,
  "maxOutputSize": 51200
}
```

| フィールド | 説明 | デフォルト値 |
|---|---|---|
| `allowedDirectories` | コマンドが操作可能なディレクトリ | なし（必須） |
| `allowCommands` | 許可コマンドのリスト | `[]` |
| `denyCommands` | 拒否コマンドのリスト | `[]` |
| `defaultErrorMessage` | 拒否時のデフォルトメッセージ | `""` |
| `maxExecutionTime` | 最大実行時間（秒）。`0` で無制限 | `120` |
| `maxOutputSize` | 最大出力サイズ（バイト）。`0` で無制限 | `51200` |

### サブコマンド検証

コマンドに対して許可するサブコマンドを指定できます。各サブコマンドは以下の形式で指定可能です：
- 単純な文字列（サブコマンド名のみ）
- 追加の制約を含むオブジェクト

**単純なサブコマンド指定：**
```json
{
  "command": "git",
  "subCommands": ["status", "pull", "fetch"]
}
```

### フラグ拒否 (denyFlags)

任意のネスト階層でコマンドやサブコマンドの特定のフラグを拒否できます。強制プッシュや強制再作成などの危険な操作を防ぐのに便利です。

**例：git push の危険なフラグを拒否**
```json
{
  "command": "git",
  "subCommands": [
    {
      "name": "push",
      "denyFlags": ["-f", "--force", "--force-with-lease"],
      "message": "強制プッシュは許可されていません"
    }
  ]
}
```

ユーザーが `git push -f` を実行すると、カスタムメッセージとともにコマンドがブロックされます。

### 再帰的サブコマンド

サブコマンドは任意の深さにネストでき、各階層で独自の `denyFlags` を設定できます。これにより、深くネストされたコマンド構造をきめ細かく制御できます。

**例：Docker Compose の再帰的な検証**
```json
{
  "command": "docker",
  "subCommands": [
    "ps",
    "logs",
    {
      "name": "compose",
      "subCommands": [
        {
          "name": "up",
          "denyFlags": ["--force-recreate"],
          "message": "強制再作成は許可されていません"
        },
        "down",
        "logs"
      ]
    }
  ]
}
```

この設定では `docker compose up` は許可されますが、`docker compose up --force-recreate` はブロックされます。

### サブコマンド拒否

`denySubCommands` を使用して、特定のサブコマンドを明示的に拒否することもできます：

```json
{
  "command": "git",
  "subCommands": ["status", "pull", "push"],
  "denySubCommands": ["reset", "revert"]
}
```

### グローバルフラグ (globalFlags / denyGlobalFlags)

`git -C /path status` や `git --no-pager log` のように、サブコマンド *より前* に
置かれるフラグを許可するには `globalFlags` を使います。設定しない場合、これら
先頭のフラグは未知のサブコマンドとして扱われ拒否されます。

`globalFlags` の各エントリは文字列（値なしフラグ）または `{name, takesValue}`
形式のオブジェクトを取れます。`takesValue: true` のフラグは次の引数を値として
消費します（`-C <path>` 形式と `-C=<path>` の両方を認識）。値が `<path>` の
場合は既存の `allowedDirectories` 検証で許可ディレクトリ外なら弾かれます。

```json
{
  "command": "git",
  "globalFlags": [
    "--no-pager",
    { "name": "-C", "takesValue": true },
    { "name": "--git-dir", "takesValue": true }
  ],
  "subCommands": ["status", "log"]
}
```

これにより `git -C /tmp/repo status` や `git --no-pager log` が通ります。

`denyGlobalFlags` は引数列のどこに現れてもブロックします（先頭限定ではない）。
`--exec-path` や `--upload-pack` のような危険なグローバルフラグの遮断に使用します。

```json
{
  "command": "git",
  "denyGlobalFlags": [
    "--exec-path",
    { "name": "--upload-pack", "message": "Custom upload-pack is not allowed" }
  ]
}
```

### 完全な設定例

以下をカバーする包括的な例は `sample-config.json` を参照してください：
- 単純な許可コマンド
- サブコマンド制限付きコマンド
- `denyFlags` 付きサブコマンド
- ネストされたサブコマンド（例：`docker compose`）
- サブコマンド前のグローバルフラグ（例：`git -C <path>`）
- カスタムメッセージ付きの明示的な拒否コマンド

## 設計と実装

Secure Shell Server は以下のコンポーネントによるモジュラー設計になっています：

1. **Validator**: 許可リストに基づいてシェルコマンドを解析・検証します。
2. **Runner**: 安全なカスタムランナーを使用して検証済みコマンドを実行します。
3. **Config**: 許可リスト設定とランタイム設定を管理します。
4. **Logger**: すべてのコマンド試行と結果の詳細なログを提供します。
5. **Server**: 安全なシェル実行サービスのための MCP インターフェースです。

## セキュリティに関する考慮事項

- 明示的に許可リストに登録されたコマンドのみ実行可能です。
- ファイルシステムアクセスは指定されたディレクトリに制限されます。
- コマンド実行は設定可能なタイムアウトで制約されます。
- スクリプトは実行前に検証され、危険な操作を防止します。
- `find` や `xargs` など他のコマンドを実行する可能性のあるコマンドには特別な処理が施されます。
- パス引数は検証され、制限領域へのアクセスを防止します。
- `denyFlags` を使用して、任意のサブコマンド階層で危険なフラグをブロックできます。

### 制限事項

- すべての高度な攻撃やコマンドチェーン技術を防ぐことはできません。
- 特定のエッジケースではコマンドインジェクションが可能な場合があります。
- セキュリティの有効性は適切な設定に大きく依存します。
- **フラグマッチング**: フラグ拒否は完全一致のみで動作します：
  - 結合ショートフラグ（例：`-fv` に含まれる `-f`）は検出されません
  - `--flag=value` 形式はフラグ名部分の完全一致が必要です
  - ポリシー設計時にこれらのパターンを考慮してください

## 開発

### 前提条件

- Go 1.20 以降
- `mvdan.cc/sh/v3` パッケージ

### ビルド

```bash
make build
```

### テスト

```bash
make test
```

### リント

```bash
make lint
```

## ライセンス

本プロジェクトは LICENSE ファイルに記載された条件に基づいてライセンスされています。

### サードパーティライセンス

本プロジェクトは以下のサードパーティライブラリを使用しています：

- `mvdan.cc/sh/v3`: BSD-3-Clause ライセンス
