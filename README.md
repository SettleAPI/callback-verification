# Verifying signatures from Settle

Whenever Settle is sending callbacks to the client over HTTPS the request from Settle is signed using the same **RSA** method as [described on our documentation site](https://support.settle.eu/hc/en-150/articles/4407317324689). The client should authenticate callbacks from Settle by verifying the signature given by Settle in the Authorization header of the request.

The Public Keys can be [downloaded from here](https://support.settle.eu/hc/en-150/articles/4407325118225-Verifying-signatures-from-Settle).
