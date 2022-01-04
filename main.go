package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/jcouyang/fizpop/slices"
	"github.com/jcouyang/fizpop/tuples"
)

type EncryptReq struct {
	Recipients []string
	Binary bool
	Content string
	Passphrase string
}

type DecryptReq struct {
	Identities []string
	Binary bool
	Content string
	Passphrase string
}
type GenKeyResp struct {
	PublicKey string
	PrivateKey string
}

func GenerateIdentity() (r GenKeyResp, e error) {
	k, err := age.GenerateX25519Identity()
	if err != nil {return r, err}
	return GenKeyResp{
		PublicKey: k.Recipient().String(),
		PrivateKey: k.String(),
	}, nil
}

func GeneratePassphrase() string {
	var words []string
	for i:=0;i<10;i++{
		words = append(words, randomWord())
	}
	return strings.Join(words, "-")
}

type EncryptResp struct {
	Status int `json:"-"`
	ErrorMessage string `json:",omitempty"`
	Content string
	Recipients []string
}

type DecryptResp struct {
	Status int `json:"-"`
	ErrorMessage string `json:",omitempty"`
	Content string
	Identities []string
}

func Encrypt(req EncryptReq) (r EncryptResp, e error) {
	var recipients []age.Recipient
	if len(req.Recipients) > 0 {
		recipients = slices.Map(func(recipient string) age.Recipient {
			switch {
			case strings.HasPrefix(recipient,"ssh-"):
				r, _ := agessh.ParseRecipient(recipient)
				return r
			case strings.HasPrefix(recipient, "age1"):
				r,_ := age.ParseX25519Recipient(recipient)
				return r
			}
			return nil
		})(req.Recipients)
	}else{
		var pass string
		if len(req.Passphrase) > 0 {
			pass = req.Passphrase
		} else {
			pass = GeneratePassphrase()
		}
		r, _ := age.NewScryptRecipient(pass)
		recipients = []age.Recipient{r}
	}
	out := &bytes.Buffer{}
	armorW := armor.NewWriter(out)
	_, err := tuples.FlatMap(func(w io.WriteCloser) (r int, e error) {
		r, e = io.WriteString(w, req.Content)
		w.Close()
		armorW.Close()
		return
	})(age.Encrypt(armorW, recipients...))

	if err != nil {
		return r, err
	}

	return EncryptResp{
		Content: out.String(),
		Recipients: slices.Map(func(r age.Recipient) string {
			return fmt.Sprint(r)
		})(recipients),
	}, nil

}

func Decrypt(req DecryptReq) (DecryptResp, error) {
	var identities []age.Identity
	if len(req.Identities)>0 {
		identities = slices.Map(func(id string) age.Identity {
			switch {
			case strings.HasPrefix(id,"ssh-"):
				r, e := agessh.ParseIdentity([]byte(id));if e != nil {return nil}
				return r
			case strings.HasPrefix(id, "AGE-SECRET-KEY-1"):
				r,e := age.ParseX25519Identity(id);if e != nil {return nil}
				return r
			}
			return nil
		})(req.Identities)
	}else {
		r, _ := age.NewScryptIdentity(req.Passphrase)
		identities = []age.Identity{r}
	}
	r, err := age.Decrypt(armor.NewReader(strings.NewReader(req.Content)), identities...)
	if err!= nil {
		return DecryptResp{
			Status: 500,
			ErrorMessage: err.Error(),
		}, err
	}
	c, _ := io.ReadAll(r)
	return DecryptResp{
		Content: string(c),
		Identities: slices.Map(func (i age.Identity) string {
			return fmt.Sprint(i)
		})(identities),
	},nil
}
func Handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	switch req.RequestContext.ResourcePath {
	case "/encrypt":
		var body EncryptReq
		encrypt := tuples.FlatMap(Encrypt)
		marshal := tuples.FlatMap(json.Marshal)

		resp, err := marshal(encrypt(body, json.Unmarshal([]byte(req.Body), &body)))
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode:        500,
				Body:              err.Error(),
			}, nil
		}
		return events.APIGatewayProxyResponse{
			StatusCode:        200,
			Body:              string(resp),
		}, nil
	case "/decrypt":
		var body DecryptReq
		decrypt := tuples.FlatMap(Decrypt)
		marshal := tuples.FlatMap(json.Marshal)

		resp, err := marshal(decrypt(body, json.Unmarshal([]byte(req.Body), &body)))
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode:        500,
				Body:              err.Error(),
			}, nil
		}
		return events.APIGatewayProxyResponse{
			StatusCode:        200,
			Body:              string(resp),
		}, nil
	case "/keygen":
		r, _ := GenerateIdentity()
		rr, _ := json.Marshal(r)
		return events.APIGatewayProxyResponse{
			StatusCode: 200,
			Body: string(rr),
		}, nil
	}
	return events.APIGatewayProxyResponse{
		StatusCode:        404,
	}, nil
}

func main(){
	lambda.Start(Handler)
}
