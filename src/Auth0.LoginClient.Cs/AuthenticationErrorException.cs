using System;

namespace Auth0.LoginClient
{
    public class AuthenticationErrorException : Exception
    {
        public AuthenticationErrorException()
        {
        }

        public AuthenticationErrorException(string message) : base(message)
        {
        }
    }
}