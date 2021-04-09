local os = require "os"
local util = require "util"

xpcall(function ()
    if ngx.ctx.enc_data then
        local data = ngx.ctx.enc_data
        data=data[2]
        local log_name = "/usr/local/nginx/conf/lua/log/enc_data.log"
        local  f = assert(io.open(log_name,'a'))
        f:write(os.date("%Y-%m-%d %H:%M:%S ")..data.."\n")
        f:close()
    end
end, function (err)
    util.log(err)
end)