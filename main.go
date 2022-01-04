package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/jcouyang/fizpop/slices"
)

type EncryptReq struct {
	Recipients []string
	Armor bool
	Content string
	Passphrase string
}

type EncryptResp struct {
	Content string
}

func Encrypt(req EncryptReq) EncryptResp {
	if len(req.Recipients) > 0 {
		recipients := slices.Map(func(recipient string) age.Recipient {
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
		out := &bytes.Buffer{}
		w, _ := age.Encrypt(out, recipients...)
		io.WriteString(w, req.Content)
		return EncryptResp{
			Content: out.String(),
		}
	} else {
		return EncryptResp{
			Content: "out.String()",
		}
	}
}

func Handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	switch req.RequestContext.ResourcePath {
	case "/encrypt":
		var body EncryptReq
		json.Unmarshal([]byte(req.Body), &body)
		resp, _ := json.Marshal(Encrypt(body))
		return events.APIGatewayProxyResponse{
			StatusCode:        200,
			Body:              string(resp),
		}, nil
	}
	return events.APIGatewayProxyResponse{
		StatusCode:        404,
	}, nil
}

func main(){
	lambda.Start(Handler)
}
