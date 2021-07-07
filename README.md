# Verifying signatures from Settle

Whenever Settle is sending callbacks to the client over HTTPS the request from Settle is signed using the same **RSA** method as [described on our documentation site](https://settle.dev/api/guides/introduction/authentication/). The client should authenticate callbacks from Settle by verifying the signature given by Settle in the Authorization header of the request.

The Public Key used by Settle in test environments can be [downloaded here](https://raw.githubusercontent.com/SettleAPI/callback-verification/master/testserver-pub.pem).

The Public Key for the production environment can be obtained by [contacting Settle](https://settle.eu/contact/).
