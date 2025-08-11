[日本語](./README.md)

# Ferri

A Docker image registry written in Rust.

> [!WARNING]
> This is highly experimental.
> Although there are integration tests, they are not extensive enough to guarantee functionality.
> I do not recommend using this in production.

## Usage

Add the following to your Docker configuration.

```json
{
  "insecure-registries" : [
    "localhost:5000"
  ]
}
```

Then start the server.

```bash
cargo run
```

After that, you can pull and push images.

```bash
docker pull alpine
docker tag alpine:latest localhost:5000/alpine:latest
docker push localhost:5000/alpine:latest
# etc.
```

## License

Provided under the MIT License.
See the LICENSE file for details.
