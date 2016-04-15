Stablehand
========================================

A server provisioning system for small teams, written using IPython.

Orginally developed by the creator of Stallion CMS.

Setting up a new server
------------------------------------------------------------

1) Create a file `conf/hosts.toml` 

Add the hosts which you wish to set up:

```
[[hosts]]
host = "mydomain.com"
user = "myuser"
class = "StallionServerConf"
extra_features = ['lets-encrypt']

```

Other classes:

* StallionServerConf -- java8, nginx, tmpreaper, extra swap space
* MySqlConf -- MySQL, swap
* MySqlAndStallionConf - combo of MySQL and StallionServerConf

2) Make a users.toml file

mkpasswd -m sha-512  --rounds=4096

2) Run the `ops/ubuntu/run.ipy` script:

```
>ipython run.ipy -- --hosts-file=/my/app/conf/hosts.toml --initial --
```


3) Ongoing -- Run the `ops/ubuntu/run.ipy` script without the --initial flag

```
> run.ipy --hosts-file=/my/app/conf/hosts.toml --initial mydomain.com anyotherdomain.com
```
