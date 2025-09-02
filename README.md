[English](./README.en.md)

# Ferri とは

Rust 製の Dockerイメージ・レジストリです。

> [!WARNING]
> 非常に実験的です。
> 統合テストはありますが、そこまで多くなくて動作の保証はできません。
> 本番環境での利用は非推奨です。

## 使い方

Docker の設定に以下を追加します

```json
{
  "insecure-registries" : [
    "localhost:5000"
  ]
}
```

続いてサーバーを起動します。

```bash
cargo run
```

その後、イメージの pull や push はできます。

```bash
docker pull alpine
docker tag alpine:latest localhost:5000/alpine:latest
docker push localhost:5000/alpine:latest
# など
```

## 設定

イメージはデフォルトでメモリ上に保存されます。
永続ストレージを利用したい場合は、`--data-dir` で保存先ディレクトリを指定します。

```bash
cargo run -- --data-dir ./data
```

## ソースコードの構成

`model` モジュールと `distribution` モジュールで出来ています。

`model` モジュールでは以下を実装しています。

- `config` - OCI Image Configuration v1.0.1
- `descriptor` と `digest` - OCI Content Descriptors v1.0.1
- `index` - OCI Image Index v1.0.1
- `manifest` - OCI Image Manifest v1.0.1

`distribution` モジュールでは OCI Distribution v1.0.1 を実装しています。

## ライセンス

MIT ライセンスで提供されています。
詳細は LICENSE ファイルをご覧ください。
