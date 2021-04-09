local os = require "os"
local cjson = require "cjson"
common_path = '/usr/local/nginx/conf/lua/enc_request_data/?.lua;/usr/local/nginx/conf/lua/?/init.lua;'
package.path = common_path .. package.path
local dist_fields = require "dist_fields"
local rsa = require "rsa"
local util = require "util"


xpcall(function ()
    args = ngx.req.get_uri_args()
    if not util.array_key_exists(args, "encrypted_str") then
        ngx.status = 500
        return ngx.print("缺少参数 encrypted_str")
    end
    ngx.print(rsa.decrypt(string.gsub(args["encrypted_str"], " ", "+")))
end, function (err) 
    ngx.print(err)
    util.log("debug", err)
end)