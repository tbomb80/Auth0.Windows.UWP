using System;

namespace Auth0.LoginClient
{
    public class AuthenticationCanceledException : Exception
    {
        public AuthenticationCanceledException()
        { 
        }

        public AuthenticationCanceledException(string message) : base(message)
        {
        }
    }
}