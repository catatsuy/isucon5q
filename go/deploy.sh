#!/bin/bash

set -x

SSH_USER=isucon

for SSH_SERVER in catatsuy.asia-east1-c.isucon5-1060; do
  rsync -avz ./ $SSH_USER@$SSH_SERVER:/home/isucon/webapp/go/
  ssh -t $SSH_USER@$SSH_SERVER /bin/bash -c "/home/isucon/webapp/go/build.sh"
  ssh -t $SSH_USER@$SSH_SERVER sudo systemctl restart isuxi.go.service
done
