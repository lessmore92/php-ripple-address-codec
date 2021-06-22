# php-ripple-address-codec
Fully ported 'ripple-address-codec' from JS to PHP

## Installation
`composer require lessmore92/php-ripple-address-codec`

### Docs
This package is fully same to main repository, so docs is same. [Main Doc](https://github.com/ripple/ripple-address-codec)

### Usage Sample

```
require_once "vendor/autoload.php";

$api = new \Lessmore92\RippleAddressCodec\RippleAddressCodec();
echo $api->classicAddressToXAddress("rGWrZyQqhTp9Xu7G5Pkayo7bXjH4k4QYpf", 4294967295) . "\n"; // XVLhHMPHU98es4dbozjVtdWzVrDjtV18pX8yuPT7y4xaEHi
echo $api->classicAddressToXAddress("r3SVzk8ApofDJuVBPKdmbbLjWGCCXpBQ2g", 123, true) . "\n"; // T7oKJ3q7s94kDH6tpkBowhetT1JKfcfdSCmAXbS75iATyLD test address

var_dump($api->xAddressToClassicAddress('XVLhHMPHU98es4dbozjVtdWzVrDjtV18pX8yuPT7y4xaEHi'));
/*
 * result
array(3) {
  ["classicAddress"]=>
  string(34) "rGWrZyQqhTp9Xu7G5Pkayo7bXjH4k4QYpf"
  ["tag"]=>
  int(4294967295)
  ["test"]=>
  bool(false)
}
 */

var_dump($api->isValidXAddress('XVLhHMPHU98es4dbozjVtdWzVrDjtV18pX8yuPT7y4xaEHi'));     //true
var_dump($api->isValidClassicAddress('r3SVzk8ApofDJuVBPKdmbbLjWGCCXpBQ2g'));            //true

```
