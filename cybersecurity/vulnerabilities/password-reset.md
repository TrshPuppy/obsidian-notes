
# Vulnerabilities in Password Reset Flows
When a user requests to rest their password, the methods used by the service to handle that request can make the password/ authentication vulnerable to attackers.
## Methods
In order for the user to request a password reset, the service needs to be able to identify them/ reach out to them through separate/ side channels. *Users should always have a way to recover their account.*
### URL Tokens
When the potential user requests a reset, generate a token, attach it to the URL query string, and send the URL to the user's email. When the user gets the email, they click the link which takes them to the URL w/ the token attached. The user can then make a new password *and confirm it*.
#### Security
1. When making the token, don't use the *Host header* to authenticate the requesting user. This can make the interaction vulnerable to [Host Header Injection](/cybersecurity/TTPs/exploitation/injection/HHI.md).
2. Ensure the URL is *[HTTPS](www/HTTPS.md)*.
3. The password reset page should have the *Referrer Policy* tag set to `noreferrer`. This protects against [referrer leakage](/cybersecurity/vulnerabilities/referrer-leakage.md).
4. Prevent [brute forcing]() techniques against the token w/ protections like [rate-limiting](/cybersecurity/defense/rate-limiting.md).
### PINs
W/ PINs the general flow is a PIN is created upon password-reset request, then sent to the *actual user's* email and/ or phone number on record w/ their account.
#### Security
1. The session created from the PIN *should be limited* and only permit the user to reset their password (shouldn't persist afterwards).
2. When the user creates and confirms the new password, the *same password policy* that's used across the service should be used.
### Security Qs
Security Questions *are not a secure way to validate the user* because the answers are easy to guess/ obtain. They are good to use as a *secondary* validation method combined w/ another of the above methods.
#### Security
1. Don't use Security Qs as the *only validation method* for a user requesting to reset their password.
2. The questions should not be designed to require or encourage the user to put answers which are pieces of easily-obtainable personal information like their birthdate.
### Offline Methods
Offline methods include mechanisms like recovery codes, [hardware OTP tokens](/cybersecurity/opsec/OTP-token.md). The most common of these is recovery/ backup codes which are provided to the user when they first register. The user is then supposed to save them *in an offline secure place.*
#### Security
1. Should be at least 8-12 digits
2. Present a *single point of failure*, for example if the user loses their codes.
3. If protections like rate limiting are not in place, an attacker can easily *brute-force* them.
## General Security Measures:
### Request phase:
When the user enters the request phase of the flow, and inputs their username/email:
1. Always return a *consistent* message for both existing and non-existing user accounts.
2. Keep a consistent timeframe for the user response message. This prevents attackers from *enumerating user accounts* (i.e. if the response timeframe is different based on whether the account exists or not, an attack can differentiate b/w existent and non-existent accounts).
3. Protect against excessive/ automated submissions
4. Perform [user input sanitization](/cybersecurity/defense/input-validation.md)
### Reset Password phase:
1. Send the user an email informing them of the password change
2. 3. *Don't make changes to the account* until a valid token is presented (don't lock the account out for example).
3. The user should then *be made to login again* instead of just instantly logging them in once the password has been successfully changed.
	- Persisting the session usually *adds complexity to the code handling the session and authentication*. This *increases the likelihood* of introducing more vulnerabilities.
### Tokens/ codes/ PINs, etc:
1. These should be generated using a *cryptographically secure random number generator*.
2. Should be long enough to prevent *brute-forcing*
3. Should be *invalidated after use*

> [!Resources]
> - [OWASP: Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
