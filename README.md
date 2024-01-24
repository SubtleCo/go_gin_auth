# A basic Golang authentication service
I developed this as a start for a product I'm working on, and before I start to bend it toward my specific usecase, I thought I'd push a generic version for anyone to copy.

This service:
- Allows a user to register with an email/password
- Allows a user to securely log in via HTTPS with email/password
- Allows a logged in user to access a protected resource
- Blocks all unauthorized requests to the protected resouce

It uses:
- JWTs signed with HS256
- bcrypt hashing and salting for secure storage of hashed passwords
- the aws-sdk-go for dynamoDB functionality
- a local dynamoDB instance (though I guess it doesn't need to be local)

anyway bye
