# BCH Tx Relayer

## build and deploy

```bash
git clone https://github.com/elfinguard/cashier.git
cd cashier/

ego-go build -o cashier github.com/elfinguard/cashier

ego sign enclave.json

ego run cashier \
	--key-grantor='<kg_ip:port>' \
	--bch-rpc-info='<ip:port,username,password>'
```
