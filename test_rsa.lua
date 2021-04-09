local ffi = require('ffi')

--local rsa = ffi.load('rsa')

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

function log(name, data)
    data = FormatTable(data)
    local log_dir = "/usr/local/nginx/conf/lua/log/"
    local  f = assert(io.open(log_dir..name..".log",'a'))
    f:write(os.date("%Y-%m-%d %H:%M:%S ")..data.."\n")
    f:close()
end

--local rsa = ffi.load('rsa')
local so_path = find_shared_obj(package.cpath, "librsa.so")
local rsa = ffi.load(so_path) 

ffi.cdef[[
int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);
 
int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);
]]

local RSA_PUBLIC_KEY = [[-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAreeA6yYHULEDRgS3Vo+0
sPs25T3dGbpn6l3/HH548mTYyLefhqvma4c1Yzi44YJdIO/6IQ0illRPJseTqwkd
DPIhQeUGAB12AxwyLRCsDDy4OjTxBYIgmx7qZOwSIcY5C41fCzfS6L5dC95/2158
sLgaUJEPhZKgoMGab8FN0Y73iznlxP8+cFOxEctNWpKPwEv75xxkidZlqkFVamTz
2pkOOMmmsmRhZDKY08i51siKCFfqcyZtZx4wzoe+Rny7eUmEVNByCUBzdCwgXBvW
xw6eKfbweK//NXRgRu3EInoES1rJsu6mH4PIOsKlqDUg7vKCqkgqHVg0pUrKhXq6
jQIDAQAB
-----END PUBLIC KEY-----]]
local RSA_PRIV_KEY = [[-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAreeA6yYHULEDRgS3Vo+0sPs25T3dGbpn6l3/HH548mTYyLef
hqvma4c1Yzi44YJdIO/6IQ0illRPJseTqwkdDPIhQeUGAB12AxwyLRCsDDy4OjTx
BYIgmx7qZOwSIcY5C41fCzfS6L5dC95/2158sLgaUJEPhZKgoMGab8FN0Y73iznl
xP8+cFOxEctNWpKPwEv75xxkidZlqkFVamTz2pkOOMmmsmRhZDKY08i51siKCFfq
cyZtZx4wzoe+Rny7eUmEVNByCUBzdCwgXBvWxw6eKfbweK//NXRgRu3EInoES1rJ
su6mH4PIOsKlqDUg7vKCqkgqHVg0pUrKhXq6jQIDAQABAoIBAQClc+wjzTqIeuEy
bKpBoNe4ykmgMQt6vu6+/E8LPQi1FV1rGcicyE+hXjJdBEphwzX3cFn5uBWAERZ9
PsQvpawN9Q/PMaZT1bPBocHbPlFyExLzzgrBwtxiuTcobbGSkJUVeJtEgQgYh4Tf
FgFvJKZdO8tNe7XYz3gjeg8E5FS1Wk6MUrLaFUaey0ImXa7A9ZqR/TDv7vujKDdA
N2h1ugNJMODoOZKeJT5SO7D8i7Mmc6MmYnZ5QKTssu7jyGQb0Pit1uBP/Kt79uAp
c1Gr6wIHvVXtMVgvG/zwMotrAnqv7B1gV9vEt2Zb720trRCEqCpI3naoYr7AIEIG
1xlOCGPBAoGBANNSYK1Z2GFo6mm7aR0HVQE2d0L19vkRhwTWTWTSVqAPOJCf6KGV
tVmsyyP1IUEDq2xFzR9X8l+FIJcziF5VHcTCfW4tvggi4By5Y3B2EPRkuWwYxWMV
v+4LRyN3VSAvb+ItG0TCqTeM9u6xWsqKFQmR+Ic8hpEFJLoqLjxCxfszAoGBANKr
71yguQYzarhR+5+L6hTH4KqRPKCKOmFAzy6//Hznec5cRLH7BHGUnLgapOlHn2is
P+r7+Hq+ncYutT4HW1UNUJgP9fzh1XuUzMeunMsvB8E7RaG/vihemccq2beloIMo
vL5NJWUIkvzCYkeRPzvAh2sCtMJFd3XadU3tbnM/AoGAPA8TjvEUAEtTJA2xiCCH
Vjrmlk9Vi+AhYYyOnnLxT7hDuUbZVOM5kWz8pxGKC/JBDBqie6ABMIijhJWO0lCa
j0s/Xsr9UU6oJ0HBMzs7AlqGIGTB5LFPxRXLeBb4SJdy0vNC5r30XedgXuJlDV9F
L10fJ0Badmjh0U8fqNzJa+UCgYEAhYuISGd54nxlgkI2B4Vh9ZpeyMEYdYwqRcwX
icMaAvOZOz8yLMC6qGVUk0AQmfBVFL1cJ1FiyixbR24EZjWzp86w8DPt80gVVCmX
Rl1h90rw14UDNu2dVWnigWagbNIJVhtUyi2NLuaohqGSO1vPgckiDqvAegYfHA5H
ngaMpXECgYEAngU8XvrXpqEUyUS+dvufop0iZ5EghBPuILmJXZDomRDbv0EVeo4b
WtEnEoUGuYcG+z4EzgaUFdzFlkIRBDETxnICkFPn4W4C1ZJYrBa/9WjeaJRm8x8T
drbQ/mCePkQMdjxUhkAPi5/9fpMq88j0P6ACbcZCjcMSkcIJOo+eWEA=
-----END RSA PRIVATE KEY-----]]

local plaintext='1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234z'
local char_plaintext = ffi.new("char[?]", #plaintext)
ffi.copy(char_plaintext, plaintext)
local pub_key = ffi.new("char[?]", #RSA_PUBLIC_KEY)
ffi.copy(pub_key, RSA_PUBLIC_KEY)
local ciphetext=ffi.new("char[?]", 2048*44)
local ret = rsa.public_encrypt(char_plaintext, #plaintext, pub_key, ciphetext)
if ret==-1 then
    print('encrypt failed')
else
    print("encrypt success", ffi.string(ciphetext))
end

local pri_key = ffi.new("char[?]", #RSA_PRIV_KEY)
ffi.copy(pri_key, RSA_PRIV_KEY)
local char_decryption=ffi.new("char[?]", 2048*44)
local deResult=rsa.private_decrypt(ciphetext,ret, pri_key, char_decryption)
if deResult==-1 then
    print("decrypt failed")
else
    print("decrypt success", ffi.string(char_decryption))
end
print("-----------------")
