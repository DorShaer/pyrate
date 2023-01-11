### This directory holds the WAF signatures.
### Feel free to add or modify any WAF signature you want.
### Every file should be a function starting with 'check_', the main function inside ../pyrate.py will search in waf_signatures.py for any valid signature. 


## Example:

# 1.Edit waf_signatures and add a function:

def check_ModSecurity(response_headers, response_body):
    PATTERN = re.compile(r'(ModSecurity|NYOB|mod_security|this.error.was.generated.by.mod.security|web.server at|page.you.are.(accessing|trying)?.(to|is)?.(access)?.(is|to)?.(restricted)?|blocked.by.mod.security)', re.IGNORECASE)
    if PATTERN.search(response_body):
        return True
    return False

# 2. Edit 'wafs' list and add the name of the WAF and the name of the function:

#    {
#        "name": "ModSecurity WAF",
#        "check_function": check_ModSecurity
#    },

# 3. Save the file and run pyrate.py --waf
