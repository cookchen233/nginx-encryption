local c = {}
function c.FormatValue(val)
    if type(val) == "string" then
        return string.format("%q", val)
    end
    return tostring(val)
end

function c.FormatTable(t, tabcount)
    tabcount = tabcount or 0
    if tabcount > 5 then
        --防止栈溢出
        return "<table too deep>"..tostring(t)
    end
    local str = ""
    if type(t) == "table" then
        for k, v in pairs(t) do
            local tab = string.rep("\t", tabcount)
            if type(v) == "table" then
                str = str..tab..string.format("[%s] = {", c.FormatValue(k))..'\n'
                str = str..c.FormatTable(v, tabcount + 1)..tab..'}\n'
            else
                str = str..tab..string.format("[%s] = %s", c.FormatValue(k), c.FormatValue(v))..',\n'
            end
        end
    else
        str = str..tostring(t)..'\n'
    end
    return str
end

function c.in_array(needle, haystack)
    for k, v in ipairs(haystack) do
        if v == needle then
            return true
        end
    end
    return false
end

function c.array_key_exists(arr, key)
    for k, v in pairs(arr) do
        if k == key then
            return true
        end
    end
    return false
end

function c.explode ( _str,seperator )
    local pos, arr = 0, {}
        for st, sp in function() return string.find( _str, seperator, pos, true ) end do
            table.insert( arr, string.sub( _str, pos, st-1 ) )
            pos = sp + 1
        end
    table.insert( arr, string.sub( _str, pos ) )
    return arr
end

function c.log(data, name)
    local os = require "os"
    if not name then
        name = "debug"
    end
    data = c.FormatTable(data)
    local log_dir = "/usr/local/nginx/conf/lua/log/"
    local  f = assert(io.open(log_dir..name..".log",'a'))
    f:write(os.date("%Y-%m-%d %H:%M:%S ")..data.."\n")
    f:close()
end

return c