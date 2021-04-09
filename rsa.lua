local ffi = require('ffi')
-- local basexx = require('basexx')

local function find_shared_obj(cpath, so_name)
    local string_gmatch = string.gmatch
    local string_match = string.match
    local io_open = io.open

    for k in string_gmatch(cpath, "[^;]+") do
        local so_path = string_match(k, "(.*/)")
        so_path = so_path .. so_name

        -- Don't get me wrong, the only way to know if a file exist is trying
        -- to open it.
        local f = io_open(so_path)
        if f ~= nil then
            io.close(f)
            return so_path
        end
    end
end

--local rsa = ffi.load('rsa')
local so_path = find_shared_obj(package.cpath, "librsa.so")
local rsa = ffi.load(so_path) 

local _M = {}

ffi.cdef[[
int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);

int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);
]]

local RSA_PUBLIC_KEY = [[
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYEBxvQLjqdKiXHw533r2y6SPC
DKqtYYCt2sfbXQEVDgpSU/k/BAvr/H63XfpxgaGLW2YvpNXnlfPA7HHlWibCcrpJ
1wflLW+u7CpfiwxhsEWZnxQmoAa7H4I3HjyRaIqoZ6ADTp+KapC4Y6IoXQ3Miwgf
eIPc8xEW9D2nhbnzfwIDAQAB
-----END PUBLIC KEY-----
]]

local RSA_PRIV_KEY = [[
-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAJgQHG9AuOp0qJcf
DnfevbLpI8IMqq1hgK3ax9tdARUOClJT+T8EC+v8frdd+nGBoYtbZi+k1eeV88Ds
ceVaJsJyuknXB+Utb67sKl+LDGGwRZmfFCagBrsfgjcePJFoiqhnoANOn4pqkLhj
oihdDcyLCB94g9zzERb0PaeFufN/AgMBAAECgYAzqk2u8yOg7XAWoIOu8KwtbI8s
sFcRP66T42DCRJBIkhOps0RdR8exL4HyVWjxReUYTz6h83SGEenW478y+PVv164w
BuP5QBOChSuqaUI7bgR7OWpztLzEnpeIIzRroGVF2vQ51F3qb+LCVJt0KfgdBXVf
D/8e0hmL8dwGa+AHYQJBAMXymmLXHyAqfIjYvt5Dxly65whM0zlguA7dFZ/ikYYA
+/5jB6GqLnjZgQbfneGewVaxNr+QHdZrEE9IDZrkEu8CQQDEqJnuT1SijzfUY1lc
ZuAwgw+Ze+2bF3J3F3JsPNWCe58YW2f98e9za7PbewKhdkxiim6Qey5r9gJIS5U0
a+hxAkB+LIu4IQNYD3zeBbp0FqNkDEajhcTFuB7aapYUGelEj3AQ0LLWm5GPuqSB
6xvJ6tW2GrOZG5XJTOlSf80cQ/DFAkAnqR0KK6OU+S84PSULdo/mGLhvqsebjJoA
HJFt9MLWgtnuDpklZMJ205S9QcyhBXuYL/TmXIFbMoz5SYz4un5xAkAk8xGLbibj
I6Pom0dzqIPJ/8dOd0Ps0UqYBq+He+BpkKexeYagsDTovs6Cm8iRgwQ5VnEnQHMY
UTaXZS3SpTr/
-----END PRIVATE KEY-----
]]

function _M.encrypt(plainText)
    local str_len=#plainText
    local c_str = ffi.new("char[?]", str_len)
    ffi.copy(c_str, plainText)
    local pub_len=#RSA_PUBLIC_KEY
    local pub = ffi.new("char[?]", pub_len)
    ffi.copy(pub, RSA_PUBLIC_KEY)
    local cipherText = ffi.new("char[?]", pub_len)
    local cipherLen = rsa.public_encrypt(c_str, str_len, pub, cipherText)
    if cipherLen == -1 then
        return -1, nil
    end
    --return cipherLen, basexx.to_base64(ffi.string(cipherText, cipherLen))
    
    -- return basexx.to_base64(ffi.string(cipherText, cipherLen))
    
    local x=ngx.encode_base64(ffi.string(cipherText, cipherLen))
    -- x=string.gsub(x,"x","x1")
    -- x=string.gsub(x,"+","x2")
    -- x=string.gsub(x,"/","x3")
    -- x=string.gsub(x,"=","x4")
    return x


    -- local en_str = ffi.new("char[?]", 2048*2)
    -- local len = ibase64.encode(string.charcipherText, en_str)
    -- return ffi.string(en_str, len)
    --return ffi.string(cipherText, cipherLen)
end

function _M.decrypt(b64cipherText)
    local cipherLen = 128
    local c_str = ffi.new("char[?]", cipherLen + 1)
    -- ffi.copy(c_str, basexx.from_base64(b64cipherText))
    ffi.copy(c_str, ngx.decode_base64(b64cipherText))
    local pri = ffi.new("char[?]", #RSA_PRIV_KEY)
    ffi.copy(pri, RSA_PRIV_KEY)
    local plainText = ffi.new("char[?]", 2048)
    local plainLen = rsa.private_decrypt(c_str, cipherLen, pri, plainText)
    if plainLen == -1 then
        return nil
    end
    return ffi.string(plainText, plainLen)
end

return _M

