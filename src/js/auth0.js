function Auth0Client(domain, clientId) {

    this.AuthorizeUrl = "https://{domain}/authorize";
    this.LoginWidgetUrl = "https://{domain}/login/";
    this.ResourceOwnerEndpoint = "https://{domain}/oauth/ro";
    this.DelegationEndpoint = "https://{domain}/delegation";
    this.UserInfoEndpoint = "https://{domain}/userinfo?access_token=";
    this.DefaultCallback = "https://{domain}/mobile";

    this.domain = domain;
    this.clientId = clientId;
}

Auth0Client.prototype.Login = function (options, callback) {

    var self = this;
    var setupAuth0User = this.setupAuth0User;
    var parseResult = this.parseResult;
    var getUserInfo = this.getUserInfo;
    var userInfoEndpoint = this.UserInfoEndpoint.replace(/{domain}/, this.domain);

    if (typeof options === 'function') {
        callback = options;
        options = {};
    }

    if (!options) options = {};
    if (!callback) callback = function () { };

    options.scope = options.scope ? encodeURI(options.scope) : "openid";

    var done = function (result) {
        var endpoint = userInfoEndpoint + result.access_token;
        getUserInfo(endpoint, function (err, profile) {
            if (err) return callback(err);

            self.CurrentUser = {
                Auth0AccessToken: result.access_token,
                IdToken: result.id_token,
                Profile: profile
            };

            return callback(null, self.CurrentUser);
        });
    };

    if (options.connection && options.username) {
        // RO endpoint
        var endpoint = this.ResourceOwnerEndpoint.replace(/{domain}/, this.domain);
        var parameters = "client_id=" + this.clientId + "&connection=" + options.connection +
            "&username=" + options.username + "&password=" + options.password + "&grant_type=password&scope=" + options.scope;

        WinJS.xhr({
            type: "POST",
            url: endpoint,
            responseType: "json",
            data: parameters,
            headers: { "Content-type": "application/x-www-form-urlencoded" }
        })
        .done(function complete(result) {
            var parsedResult = JSON.parse(result.responseText);
            return done(parsedResult);
        },
        function (err) {
            return callback(err);
        });
    }
    else {
        this.getAuthenticator(options.connection, options.scope).done(function (result) {
            if (result.responseStatus === Windows.Security.Authentication.Web.WebAuthenticationStatus.errorHttp) {
                return callback(result.responseErrorDetail)
            }

            var parsedResult = parseResult(result.responseData);
            return done(parsedResult);
        },
		function (err) {
		    return callback(err);
		});
    }
}

Auth0Client.prototype.GetDelegationToken = function (targetClientId, options, callback) {

    if (typeof options === 'function') {
        callback = options;
        options = {};
    }

    // ensure id_token
    var id_token = options.id_token || this.CurrentUser.IdToken;
    delete options.id_token;

    if (!id_token) {
        return callback(new Error("You need to login first or specify a value for id_token parameter."));
    }

    var endpoint = this.DelegationEndpoint.replace(/{domain}/, this.domain);
    var parameters = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" + "&id_token=" + id_token +
                     "&target=" + targetClientId + "&client_id=" + this.clientId;

    for (var k in options) {
        if (options[k] !== undefined) {
            parameters += "&" + k + "=" + options[k];
        }
    }

    WinJS.xhr({
        type: "POST",
        url: endpoint,
        responseType: "json",
        data: parameters,
        headers: { "Content-type": "application/x-www-form-urlencoded" }
    })
    .done(function complete(result) {
        var parsedResult = JSON.parse(result.responseText);
        return callback(null, parsedResult);
    },
    function (err) {
        return callback(err);
    });
}

Auth0Client.prototype.Logout = function () {

    this.CurrentUser = null;
}

Auth0Client.prototype.getAuthenticator = function (connection, scope) {

    var auth0Url = this.AuthorizeUrl.replace(/{domain}/, this.domain);
    var loginWidgetUrl = this.LoginWidgetUrl.replace(/{domain}/, this.domain);
    var callbackUrl = this.DefaultCallback.replace(/{domain}/, this.domain);

    auth0Url += "?client_id=" + this.clientId + "&redirect_uri=" + callbackUrl + "&response_type=token&scope=" + scope + "&" + "connection=" + connection;
    loginWidgetUrl += "?client=" + this.clientId + "&redirect_uri=" + callbackUrl + "&response_type=token&scope=" + scope;

    var startUri = new Windows.Foundation.Uri(connection ? auth0Url : loginWidgetUrl);
    var endUri = new Windows.Foundation.Uri(callbackUrl);

    return Windows.Security.Authentication.Web.WebAuthenticationBroker.authenticateAsync(
		Windows.Security.Authentication.Web.WebAuthenticationOptions.none, startUri, endUri);
}

Auth0Client.prototype.getUserInfo = function (endpoint, callback) {

    WinJS.xhr({
        type: "GET",
        url: endpoint,
        responseType: "json"
    })
	.done(function complete(result) {
	    return callback(null, JSON.parse(result.responseText));
	},
	function (err) {
	    return callback(err);
	});
}

Auth0Client.prototype.parseResult = function (result) {

    var tokens = {};
    var strTokens = result.split("#")[1].split("&");

    for (var i in strTokens) {
        var tok = strTokens[i].split("=");
        tokens[tok[0]] = tok[1];
    }

    return tokens;
}