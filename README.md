# Yandex.Cloud KMS Clients

Clients for Yandex.Clouds KMS.

## Tink KMS Client for Yandex.Cloud

[![GoDoc](https://godoc.org/github.com/yandex-cloud/kms-clients-go/yckmstink?status.svg)](https://godoc.org/github.com/yandex-cloud/kms-clients-go/yckmstink)

## Installation

```bash
go get github.com/yandex-cloud/kms-clients-go/yckmstink
```

## Examples

The following code encrypts plaintext "Hello, KMS!" with keyID and then decrypts it.

```go
func EncryptAndDecrypt(token string, keyID string) {
    sdk, err := ycsdk.Build(ctx, ycsdk.Config{
        Credentials: ycsdk.OAuthToken(token),
    })
    if err != nil {
        log.Fatal(err)
    }
    
    a := yckmstink.NewYCAEAD(keyID, sdk)
    ciphertext, err := a.Encrypt([]byte("Hello, KMS!"), []byte("aad"))
    if err != nil {
        log.Fatal(err)
    }
    plaintext, err := a.Decrypt(ciphertext, []byte("aad"))
    if err != nil {
        log.Fatal(err)
    }
    // Prints "Hello, KMS!"
    log.Print(string(plaintext))
}
```

You can find more examples are in the [examples](yckmstink/examples) directory.
