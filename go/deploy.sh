#!/bin/bash

set -x

SSH_USER=isucon

cd ${HOME}/src/github.com/catatsuy/isucon5q/go
GOOS=linux GOARCH=amd64 go build -o app app.go

for SSH_SERVER in catatsuy.asia-east1-c.isucon5-1060; do
  rsync -avz ./ $SSH_USER@$SSH_SERVER:/home/isucon/webapp/go/
  ssh -t $SSH_USER@$SSH_SERVER sudo systemctl restart isuxi.go.service
done
