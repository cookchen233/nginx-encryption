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

--local rsa = ffi.load('rsa')
--local so_path = find_shared_obj(package.cpath, "libbase62x.so")
local so_path = find_shared_obj(package.cpath, "ibase64.so")
local ibase64 = ffi.load(so_path) 

ffi.cdef[[
int encode(unsigned char * plain, unsigned char* result);
]]

local text="xx"
local text_len=#text
local c_str = ffi.new("char[?]", text_len) -- str len
ffi.copy(c_str, text)

local en_str = ffi.new("char[?]", text_len*2)
local len = ibase64.encode(c_str,en_str)
print(ffi.string(en_str, len))
