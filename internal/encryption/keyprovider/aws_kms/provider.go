package aws_kms

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/opentofu/opentofu/internal/encryption/keyprovider"
)

type keyMeta struct {
	CiphertextBlob []byte `json:"ciphertext_blob"`
}

type keyProvider struct {
	Config
	svc *kms.Client
	ctx context.Context
}

func (p keyProvider) getSpec() (types.DataKeySpec, error) {
	var spec types.DataKeySpec

	for _, opt := range spec.Values() {
		if string(opt) == p.KeySpec {
			spec = opt
		}
	}

	if len(spec) == 0 {
		return spec, fmt.Errorf("Invalid key_spec %s, expected one of %v", p.KeySpec, spec.Values())
	}
	return spec, nil
}

func (p keyProvider) EncryptionKey() ([]byte, keyprovider.KeyMeta, error) {
	spec, err := p.getSpec()
	if err != nil {
		return nil, nil, err
	}

	generatedKeyData, err := p.svc.GenerateDataKey(p.ctx, &kms.GenerateDataKeyInput{
		KeyId:   aws.String(p.KMSKeyID),
		KeySpec: spec,
	})

	if err != nil {
		return nil, nil, err
	}

	return generatedKeyData.Plaintext, &keyMeta{
		CiphertextBlob: generatedKeyData.CiphertextBlob,
	}, nil
}

func (p keyProvider) DecryptionKey(rawMeta keyprovider.KeyMeta) ([]byte, error) {
	inMeta := rawMeta.(*keyMeta)

	decryptedKeyData, err := p.svc.Decrypt(p.ctx, &kms.DecryptInput{
		KeyId:          aws.String(p.KMSKeyID),
		CiphertextBlob: inMeta.CiphertextBlob,
	})

	if err != nil {
		return nil, err
	}

	return decryptedKeyData.Plaintext, nil
}
