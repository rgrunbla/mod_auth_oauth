-- Prosody IM
-- Copyright (C) 2008-2013 Matthew Wild
-- Copyright (C) 2008-2013 Waqas Hussain
-- Copyright (C) 2014 Kim Alvefur
-- Copyright (C) 2019 Rémy Grünblatt
--
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.
--

module:depends("sasl_oauthbearer");

local new_sasl = require "util.sasl".new;
local base64 = require "util.encodings".base64.encode;
local json = require "util.json";
local have_async, async = pcall(require, "util.async");

local http = require "util.http";

local nodeprep = require "util.encodings".stringprep.nodeprep;

local log = module._log;
local host = module.host;

-- Client ID and Client Secret, for "Confidential" clients
local oauth_client_id = module:get_option_string("oauth_client_id",  "");
local oauth_client_secret = module:get_option_string("oauth_client_secret",  "");

-- OAuth URLs
--
-- oauth_url_token is the URL used to check username and password for PLAIN
-- authentications
--
-- oauth_url_userinfo is the URL used to check the validity of a token for
-- OAUTHBEARER authentications

local oauth_url_token = module:get_option_string("oauth_url_token",  "");
local oauth_url_userinfo = module:get_option_string("oauth_url_userinfo",  "");

-- OAuth host used for http requests
local oauth_host = module:get_option_string("oauth_host",  "");

if oauth_client_id == "" then error("oauth_client_id required") end
if oauth_client_secret == "" then error("oauth_client_secret required") end
if oauth_url_token == "" then error("oauth_url_token required") end
if oauth_url_userinfo == "" then error("oauth_url_userinfo required") end
if oauth_host == "" then error("oauth_host required") end

local provider = {};

-- globals required by socket.http
if rawget(_G, "PROXY") == nil then
	rawset(_G, "PROXY", false)
end
if rawget(_G, "base_parsed") == nil then
	rawset(_G, "base_parsed", false)
end
if not have_async then -- FINE! Set your globals then
	prosody.unlock_globals()
	require "ltn12"
	require "socket"
	require "socket.http"
	require "ssl.https"
	prosody.lock_globals()
end

-- TODO: actually check if that's how ltn12 should be required
prosody.unlock_globals()
require "ltn12"
prosody.lock_globals()

local function async_http_request(url, payload)
	module:log("debug", "async_http_auth()");
	local http = require "net.http";
	local wait, done = async.waiter();
	local content, code, request, response;
	local ex = {
                headers = {
                        ["Content-Type"] = "application/x-www-form-urlencoded";
                        ["Content-Length"] = #payload;
                        ["Host"] = oauth_host;
                },
                method = "POST",
                source = ltn12.source.string(payload),
	}
	local function cb(content_, code_, request_, response_)
		content, code, request, response = content_, code_, request_, response_;
		done();
	end
	http.request(url, ex, cb);
	wait();
	if code >= 200 and code <= 299 then
		return true, content;
	end
	return nil;
end

local function sync_http_request(url, payload)
	module:log("debug", "sync_http_auth()");
	require "ltn12";
	local http = require "socket.http";
	local https = require "ssl.https";
	local request;
	if string.sub(url, 1, string.len('https')) == 'https' then
		request = https.request;
	else
		request = http.request;
	end
	local body_chunks = {};
	local _, code, headers, status = request{
		url = url,
                headers = {
			["Content-Type"] = "application/x-www-form-urlencoded";
			["Content-Length"] = #payload;
                        ["Host"] = oauth_host;
		},
		method = "POST",
		source = ltn12.source.string(payload),
		sink = ltn12.sink.table(body_chunks),
	};
	if type(code) == "number" and code >= 200 and code <= 299 then
		return true, table.concat(body_chunks);
	end
	return nil;
end

-- Currently, http async requests are disabled because they do not work
-- local http_request = have_async and async_http_request or sync_http_request;
local http_request = sync_http_request;

function http_test_password(username, password)
	local url = oauth_url_token;
	module:log("debug", "Testing password for user %s at host %s with URL %s", username, host, url);
	local grant_type = 'password';
	local client_id = oauth_client_id;
	local client_secret = oauth_client_secret;
	local form_data = http.formencode({ username = username, password = password, grant_type = grant_type, client_id = client_id, client_secret = client_secret });
	local ok = (http_request(url, form_data));
	if not ok then
		return nil, "not authorized";
	end
	return true;
end

function oauth_test_token(username, token, realm)
	module:log("debug", "Testing signed OAuth2 for user %s at realm %s", username, realm);
	local https = require "ssl.https";
	local url = oauth_url_userinfo;
	module:log("debug", "The URL is:  "..url);

        local form_data = string.format([[access_token=%s]], token);
        local ok, userinfo_json = http_request(url, form_data);
        if ok then
		module:log("debug", "OAuth provider confirmed valid token.");
                local userinfo = json.decode(userinfo_json);
                if userinfo then
			if username == userinfo["preferred_username"] then
				return true;
			else
				module:log("debug", "OAuth provider username mismatch.");
			end
		else
			module:log("debug", "Endpoint response is weird.");
		end
	else
		module:log("debug", "OAuth provider returned status failed: ");
	end
	module:log("warn", "Auth failed. Invalid username/token or misconfiguration.");
	return nil;
end

function provider.test_password(username, password)
	return http_test_password(username, password);
end

function provider.users()
	return function()
		return nil;
	end
end

function provider.set_password(username, password)
	return nil, "Changing passwords not supported";
end

function provider.user_exists(username)
	return true;
end

function provider.create_user(username, password)
	return nil, "User creation not supported";
end

function provider.delete_user(username)
	return nil , "User deletion not supported";
end

function provider.get_sasl_handler(session)
	local supported_mechanisms = {};
	supported_mechanisms["OAUTHBEARER"] = true;
	supported_mechanisms["PLAIN"] = true;
	return new_sasl(host, {
		plain_test = function(sasl, username, password, realm)
			return provider.test_password(username, password), true;
		end,
		oauthbearer = function(sasl, username, token, realm)
			return oauth_test_token(username, token, realm), true;
		end,
                mechanisms = supported_mechanisms
	});
end

module:provides("auth", provider);
