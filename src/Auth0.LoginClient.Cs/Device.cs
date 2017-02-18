using System.Linq;
using System.Threading.Tasks;
#if DOTNET
#else
using Windows.Networking.Connectivity;
#endif
namespace Auth0.LoginClient
{
    public class Device : IDeviceIdProvider
    {
        public Task<string> GetDeviceId()
        {
            var defaultDeviceName = "Windows Device";
#if DOTNET
#else
            var hostname = NetworkInformation.GetHostNames()
                .FirstOrDefault(name => name.DisplayName.Contains(".local"));

            if (hostname != null)
            {
                defaultDeviceName = hostname.DisplayName.Replace(".local", string.Empty);
            }
#endif
            return Task.FromResult<string>(defaultDeviceName);
        }
    }
}
