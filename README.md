# PyJectRule

Code based on PyRules project at https://github.com/DanNegrea/PyRules

The goal is to make testing multi-staged APIs easier, and the user defined rules
more intuitive.

Allows Burp user to embed markers/tags into requests which can then be passed
through this tool, and have the user defined rules on replacing the markers
with strings of their choice.


## Getting Started

Git clone this project.

### Prerequisites

* Burp Suite
* Linux
* Python 2.7+

### Installing

* Install Burp Suite
```
https://portswigger.net/burp/communitydownload
```
* Install PyRules
```
git clone https://github.com/muttiopenbts/PyRules.git
```
* Copy pyrules-script.py and paste into PyRules.
* Add global variables


* Usage
Define your rules within the python dictionary 'settings', 'tags' list.
```
settings = {
	'tags': [
		{'id':"{{customer_id}}", 'type':'string','content':'201803051',},
		{'id':"{{code}}", 'type':'string','content':code,},
		{
			'id':"{{service_key}}",
			'type':'code',
			'content':[generate_signature,
			{
				'signer':signer,
				'command':command,
				'multi_tenant_priv_key':multi_tenant_priv_key,
				'service_name':service_name,
				'messageInfo':messageInfo,
				'helpers':helpers,
			},]
		,},
	],
}
```

'id' = 		{{[a-zA-Z_]}}. This is the identifier that you will place in your http
			requests.

'type' = 	'string' or 'code'. Refer to 'content' for definition.

'content' =	Based on 'type' field.
			'string' types are a one-to-one replacement with 'content' value when
			a match is made against an 'id'/tag/marker.
			'string' can be a literal or a varible.
			'code' will call a user defined function to
			dynamically generate the replacement text.
			The format for a code call is a list of length 2, index 0 = function
			name, and index 1 = dictionary of keyword arguments to the function.

Your global variables should be defined within PyRules and must have same name
as your tag
```
settings['tag'][0]['content']
```

Markers/tags are currently supported in Burp repeater and intruder tools.
Tags can be placed in the url, header or body portions of a request.
Example request:
```
POST /root/login/auth HTTP/1.1
Host: myapi.net
Connection: close
Content-Type: application/json
Content-Length: 78

{
    "code": "{{code}}",
    "redirectUri": "https://mycloud.com/oauth"
}
```
To view the newly modified request(s), you must install Burp's 'Custom logger'
extension.


## Built With

* Python 2.7

## Versioning

V0.1.

## Authors

* **Mutti K** - *Initial work*

## License

https://www.gnu.org/licenses/gpl-3.0.en.html

## Acknowledgments

* PyRules Extension
