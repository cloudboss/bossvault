// Copyright © 2016 Joseph Wright <rjosephwright@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package lib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
)

const CiphertextLength = 204

type KmsClient struct {
	*kms.KMS
}

type S3Client struct {
	*s3.S3
}

type BossVaultClient struct {
	Kms *KmsClient
	S3  *S3Client
}

func NewBossVaultClient() *BossVaultClient {
	s := session.New()
	return &BossVaultClient{
		Kms: &KmsClient{kms.New(s)},
		S3:  &S3Client{s3.New(s)},
	}
}

func (kc *KmsClient) DataKey(keyId string) (out *kms.GenerateDataKeyOutput, err error) {
	keySpec := "AES_256"
	out, err = kc.GenerateDataKey(&kms.GenerateDataKeyInput{
		KeyId:   &keyId,
		KeySpec: &keySpec,
	})
	if err != nil {
		return
	}
	return
}

func (kc *KmsClient) KeyIdForAlias(alias string) (string, error) {
	var keyId string
	var err error

	aliases := []*kms.AliasListEntry{}
	err = kc.ListAliasesPages(
		&kms.ListAliasesInput{},
		func(out *kms.ListAliasesOutput, lastPage bool) bool {
			aliases = append(aliases, out.Aliases...)
			return lastPage
		},
	)
	if err != nil {
		return keyId, err
	}

	fullAlias := fmt.Sprintf("alias/%s", alias)
	for _, a := range aliases {
		if *a.AliasName == fullAlias {
			keyId = *a.TargetKeyId
			break
		}
	}
	if keyId == "" {
		err = fmt.Errorf("No such alias found")
	}

	return keyId, err
}

func RandomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func ContentBytes(content string) ([]byte, error) {
	var buf []byte
	var err error
	parts := strings.Split(content, "@")
	if len(parts) > 1 && parts[0] == "" && len(parts[1]) > 0 {
		path := parts[1]
		if file, err := os.Open(path); err != nil {
			return nil, err
		} else {
			defer file.Close()
			if buf, err = ioutil.ReadAll(file); err != nil {
				return nil, err
			}
		}
	} else {
		buf = []byte(content)
	}
	return buf, err
}

func NsFrom(artifact string) (ns string, err error) {
	parts := strings.Split(artifact, "/")
	if len(parts) == 1 {
		err = fmt.Errorf("Invalid artifact name")
	} else {
		ns = parts[0]
	}
	return ns, err
}

func (c *BossVaultClient) EncryptAndStore(bucket, artifact, content string) error {
	namespace, err := NsFrom(artifact)
	if err != nil {
		return err
	}

	plaintext, err := ContentBytes(content)
	if err != nil {
		return err
	}

	keyId, err := c.Kms.KeyIdForAlias(namespace)
	if err != nil {
		return err
	}

	dk, err := c.Kms.DataKey(keyId)
	if err != nil {
		return err
	}

	encrypted, err := Encrypt(plaintext, dk.Plaintext)
	if err != nil {
		return err
	}

	sse := "aws:kms"
	key := fmt.Sprintf("%s.enc", artifact)
	payload := append(dk.CiphertextBlob, encrypted...)
	body := bytes.NewReader(payload)
	_, err = c.S3.PutObject(
		&s3.PutObjectInput{
			Bucket:               &bucket,
			Key:                  &key,
			Body:                 body,
			ServerSideEncryption: &sse,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (c *BossVaultClient) RetrieveAndDecrypt(namespace, bucket, artifact string) ([]byte, error) {
	obj, err := c.S3.GetObject(
		&s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &artifact,
		},
	)
	if err != nil {
		return nil, err
	}

	content, err := ioutil.ReadAll(obj.Body)
	if err != nil {
		return nil, err
	}

	encryptedKey := content[:CiphertextLength]
	payload := content[CiphertextLength:]

	dataKey, err := c.Kms.Decrypt(
		&kms.DecryptInput{
			CiphertextBlob: encryptedKey,
		},
	)
	if err != nil {
		return nil, err
	}

	decrypted, err := Decrypt(payload, dataKey.Plaintext)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

func Encrypt(plaintext, key []byte) ([]byte, error) {
	var block cipher.Block
	var err error
	var iv []byte

	if block, err = aes.NewCipher(key); err != nil {
		return nil, err
	}

	if iv, err = RandomBytes(aes.BlockSize); err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext, plaintext)

	return append(iv, ciphertext...), nil
}

func Decrypt(ciphertext, key []byte) ([]byte, error) {
	iv := ciphertext[:aes.BlockSize]
	payload := ciphertext[aes.BlockSize:]
	decrypted := make([]byte, len(payload))

	if block, err := aes.NewCipher(key); err != nil {
		return nil, err
	} else {
		cfb := cipher.NewCFBDecrypter(block, iv)
		cfb.XORKeyStream(decrypted, payload)
	}

	return decrypted, nil
}