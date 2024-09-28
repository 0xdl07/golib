package encrypt

import (
	b64 "encoding/base64"
	"testing"
)

var (
	PublicKey  = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUEwVVJqK0hYYStNU2o0NVBsYVVKagppb2lWTElwSitnM2kxRjF1akdBYjZ5YXRCQWNla2tiMDFwMmxUelpuVEMzTXNMMDgvVTJWdW1EdmJITHdBWlBBCkc5N0dxdStCY0kzbnFyOUFXaHM0TXQydjYwc1FEWkloZElBamY5L1JJTU9peUJwR1pYOGhyS0cvSXhudTA4cGoKZlpSV3NlSG55dnlubE0vTUhNdjFOWmJZdnFoekJOL1cvU1VjVFJnVDVkTjZlSTJrZkx4UFZMZ0pzRlRwNzE1RgppNWxUYWhjREM3SUg5WnBGYU9VNzh2QzhQMkw4NnI1bmxpeUV5bld1V2tnUFZCZndMcFdLcGpsUEtqalJLVFM4ClM5ZjFuTEQwbjE2NEhvMGFabDRxRlg0c0w4RGFoOERnaVR0OWVEVEF5NzdvaDV0eFQxdlRSWS9SS3o4UGEyaEYKN3dJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
	PrivateKey = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2d0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktrd2dnU2xBZ0VBQW9JQkFRRFJSR1A0ZGRyNHhLUGoKaytWcFFtT0tpSlVzaWtuNkRlTFVYVzZNWUJ2ckpxMEVCeDZTUnZUV25hVlBObWRNTGN5d3ZUejlUWlc2WU85cwpjdkFCazhBYjNzYXE3NEZ3amVlcXYwQmFHemd5M2EvclN4QU5raUYwZ0NOLzM5RWd3NkxJR2tabGZ5R3NvYjhqCkdlN1R5bU45bEZheDRlZksvS2VVejh3Y3kvVTFsdGkrcUhNRTM5YjlKUnhOR0JQbDAzcDRqYVI4dkU5VXVBbXcKVk9udlhrV0xtVk5xRndNTHNnZjFta1ZvNVR2eThMdy9Zdnpxdm1lV0xJVEtkYTVhU0E5VUYvQXVsWXFtT1U4cQpPTkVwTkx4TDEvV2NzUFNmWHJnZWpScG1YaW9WZml3dndOcUh3T0NKTzMxNE5NREx2dWlIbTNGUFc5TkZqOUVyClB3OXJhRVh2QWdNQkFBRUNnZ0VBWnRQdk42aFp0OEdRTW9SNnh0VWJhbmdnck9rcTNwY3lMVjNYczF5S2UycmUKdTByd1I3cGNGcFVTSkxFNzR0L2lZN29wSE9LaHZ4cGdxMjV5NXFOK1UzT05OWE5JckZEZVZEVnozcExmYzRjaApLVUlTR2trQzdXY0ZpcEVsQnE5NjdrNlM1czZvY2xac1FFZys1WXplaEZkK25odStOUzBlLzIxNEEzSnBCREkrCnJMZ05EYm9uRGVlWGJGRXRENXBjcVFPbjNUTGdOT3F3c2NBOGx1L1lraUdIT3E4Unp4Q1Z5UHZsNVV4VGdycisKazZpL3VSRHRNZm1lK2l6R3BsNUU4cE1zQnU4ck1vUXlSQzZuZVQ2OHlTZ05rMS9ULzVCWHV4Q2RuemRoL3R1VQpieXhQOEJydjBMOC9jSFhJNEZZWHlSRmsvUDduT2diQmZZa0Z4VXdvS1FLQmdRRHUxUjRyVGNKMEh6M0pqdWpzCkdGOFVNUkpwY244dUhlZ0NIMmlJNjVuRU9hWjBldDFWcVBkdWlicEdCZy94M21UaWNvNjNzYTNkamt6dC8zUEwKUDE0OWtiaXBoV25DNEVFQkc5dGM1dUJmQ3IvYWJCaWNHRTZGUTdaSkQvNzZKZEJyRDJZQUtyVVF1YUttTVhIOApVL1hvNHI4R2Foc053K3ZVQmlkbEZEeFF6UUtCZ1FEZ1R6bXNYZGJvTkZtY2tEY0w0S0kxOTNseFpISFMvL3c1CmJCd0VuWkNBdzRvUm5IM2pmVWIvY3hpQkRNa0dVMXdhYk1lbXdmV0FLSDN2MkgvdjJONTArUjZ5Wm9jNUpRY2IKMWU2RFBxM1VGOTUxUTFRN0huZlRyL0xOZmJyb1gwOVoxdTlIVFJHSlBMWmJMNW9ZUTJ2c2tGRmhEdzErdVZmbQpQM0R4MEFPQnF3S0JnUUM4QkdpNHZJR051eDZBTTVJb2MxTSthUmRPamdXVFA1WHJQZUNra1owK3ZnZk5nUUFICnRIbjl1azA3WFFCbWI2YktJbGM2UTVWVmF2WWpFc3lNdi9rbnpUVXJ0MHk0VHFTK0E3a2duTjBiMVRHTitUVXkKaFd3ak8xZ2drb2d2VTErTk9OVWE0b1FpZzVHSTlqbis0L1llZllyV3VPZE5ZZVNneUt0d3hvcHBMUUtCZ1FEVgp0Mlp4N2k3V3F4bythOEdtMVc1NEVNUnEzNUw3d042bUwzVTZpSTJud2FjSlJKdEZacFdBeWo2c3BtdmFWUTVLCk54NjZxYzZwUHV0TzNHNTVMWjQyd1MwWU9VdlpqSWdMWTNlUElPY3FUMXVyU20wMHJzRG90cG1XWkpieTAreWMKNG9hMDNwODRyTm5xWTU1a1E4ak9hbXEvR1VKNFhVdDhtekdYaytQalpRS0JnUURHQXA0SkdIc3p6OTFiS2YxKwpVb3NicjNYVjlxVlRSdzVpc0pwVXQzamdoaWVTWFBPK0IxZnM3dmlFcTVTbDZhUk5UOVI5bEFoYTlsdjM3a3pHCjhlRFczOGUvMHlZVDBDaUlxSDA1anBaMWdUSUxJdThNazVQOVd2L2tocGkwVm8zL3NhcWtuQ01lVzVvMDRqYzYKVzc0a0NCNkdHV1RwOHA0ZVRycTZZSkoxaEE9PQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg=="
)

func TestGenRsaKey(t *testing.T) {
	privateKey, publicKey := GenRsaKey(2048)
	t.Log("privateKey:", privateKey)
	t.Log("publicKey:", publicKey)
	priK := b64.StdEncoding.EncodeToString([]byte(privateKey))
	pubK := b64.StdEncoding.EncodeToString([]byte(publicKey))
	t.Log("privateKey:", priK)
	t.Log("publicKey:", pubK)
}

func TestRsaEncryptBase64(t *testing.T) {
	originalData := "hello, world"
	privateKey, publicKey := GenRsaKey(2048)

	encryptedData, err := RsaEncryptBase64(originalData, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("encryptedData:", encryptedData)
	priKE := b64.StdEncoding.EncodeToString([]byte(privateKey))
	priKD, _ := b64.StdEncoding.DecodeString(priKE)
	dencryptedData, err := RsaDecryptBase64(encryptedData, string(priKD))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("dencryptedData:", dencryptedData)
	if dencryptedData != originalData {
		t.Fatal("dencryptedData != originalData")
	}
}

func TestSinganture(t *testing.T) {
	originalData := "hello, world"
	privateKey, err := b64.StdEncoding.DecodeString(PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignBase64(originalData, string(privateKey))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := b64.StdEncoding.DecodeString(PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	isOk, err := VerifySignWithBase64(originalData, signature, string(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("isOk:", isOk)
}
