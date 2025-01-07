
# GoPhish
Init.
[GoPhish](https://docs.getgophish.com/user-guide)i s a tool which helps to facilitate email [phishing](../phishing.md) campaigns.
## Use
### `{{.Tracker}}`
In the email body, place a `{{.Tracker}}` tag at the end. This allows GoPhish to track interaction with the email from the user. The `{{.Tracker}}` tag is really just an alias for `img src={{.TrackerUrl}}` with `{{.TrackingUrl}}` which is the URL to GoPhish's tracking handler.

> [!Resources]
> - [GoPhish Docs](https://docs.getgophish.com/user-guide)