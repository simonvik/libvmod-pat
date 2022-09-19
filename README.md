# Varnish vmod for Private Access Tokens

This vmod implements support for type `0x0002` tokens used by apple devices.

*This code might be very buggy and unsafe and its mostly a PoC*

```
# Usage: 

		sub vcl_init {

            # Init with public key, it will in the future fetch the directory
			new ppat = pat.pat("MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAysdWcET7XEBJbjsM-QPnk89xWDkmQy-hPRdvbbXiwMtWc8D2WJPfaE0diWcjbKjpJCJww_gzDIZgtTKjCs8Grya4sTCHCdGbC-_pDB4I5thB50fGQif5jLQ5wHY9J6ZGITmfcBGpZa1jT56jwcJOStgIWsvM5_vPt82NkzvsxAqQlu0x6XJ2X4htfslcRceLekxhYk-4qIzapMeU9fOvKX8002AZPYnF9H1aJhvwSGfO_vmpw0MIXB5ULOlsGnYSFgxnRcukfetBtUP7BOG6-IhOCowsfN_ExGQ6KQV89gf4nvr4WXWF6de20vnY13cFdw-iN3FVIQcqjEuvLgkqJwIDAQAB");
		}

        sub vcl_recv {
            # Using demo-pat.issuer.cloudflare.com issuer as an example

            if(ppat.validate_header(req.http.Authorization, "demo-pat.issuer.cloudflare.com", "example.com", "NONCE")){
                return(synth(200, "Woho, authed"));
            }
        }

        sub vcl_deliver {
            # Using demo-pat.issuer.cloudflare.com issuer as an example
            
			set resp.status = 401;
	    	set resp.http.www-authenticate = ppat.generate_token_header("demo-pat.issuer.cloudflare.com","example.com", "NONCE");
        }

```


For more reading:

https://www.ietf.org/archive/id/draft-ietf-privacypass-auth-scheme-05.html

https://blog.cloudflare.com/eliminating-captchas-on-iphones-and-macs-using-new-standard/

https://www.fastly.com/blog/private-access-tokens-stepping-into-the-privacy-respecting-captcha-less

https://www.ietf.org/archive/id/draft-ietf-privacypass-architecture-03.html

https://developer.apple.com/news/?id=huqjyh7k