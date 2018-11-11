百度网盘API
====================================

特别感谢
------------
本API是[baidupcsapi](https://github.com/ly0/baidupcsapi)的NodeJS移植版

Installation
------------
```shell
$ npm install --save baidupanapi
```

TIP
------------
一下所有的例子皆使用TypeScript

Usage
------------
```TypeScript
import PCS from "baidupanapi";

let pcs = new PCS("username", "password")
pcs.init.then(() => {
    //DO SOMETHINE HERE
}).catch(console.error)
```

Simple Example
-----------
```TypeScript
import PCS from "baidupanapi";

let pcs = new PCS("username", "password")
pcs.init
    .then(() => pcs.quota()).then(console.log)
    .then(() => pcs.list_files("/")).then(console.log)
    .catch(console.error)