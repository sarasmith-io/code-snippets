import os, sys, time
import ldap
import ldap.modlist as modlist
import grampg
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
from scripts.hubot_script import *

class ManageLdap(HubotScript):
    """
    Manage ldap from hubot
    """

    def __init__(self):
        try:
            os.environ["HUBOT_LDAP_SERVER"]
        except KeyError:
            return "Please set the environment variable HUBOT_LDAP_SERVER"
        try:
	    os.environ["HUBOT_LDAP_USERNAME"]
        except KeyError:
            return "Please set the environment variable HUBOT_LDAP_USERNAME"
        try:
            os.environ["HUBOT_LDAP_PASSWORD"]
        except KeyError:
            return "Please set the environment variable HUBOT_LDAP_PASSWORD"

    @respond(
        r'''
        .*ldap\snext\sgid # show the next available gid
        '''
    )
    def nextgid(self, message, matches):
        """
        Get the next available gid from LDAP 
        """
	ldap_server=os.environ['HUBOT_LDAP_SERVER']
        ldap_username=os.environ['HUBOT_LDAP_USERNAME']
        ldap_password=os.environ['HUBOT_LDAP_PASSWORD']

	try:
	     #Open a connection to the LDAP server.
             l = ldap.open(ldap_server,1389)
	     ## searching doesn't require a bind in LDAP V3.  If you're using LDAP v2, set the next line appropriately
	     ## and do a bind as shown in the above example.
	     # you can also set this to ldap.VERSION2 if you're using a v2 directory
	     # you should  set the next option to ldap.VERSION2 if you're using a v2 directory
             l.protocol_version = ldap.VERSION3	
	     #bind as manager if you need to perform write tasks. Otherwise anonymous will do for a read!
             l.simple_bind_s(ldap_username,ldap_password)
	except ldap.LDAPError, error:
	     return error
             # print the ldap error if something broke.

	## The next lines set the BASEDN and searchscope to only show groups, as we want to get the next gid
	baseDN = "ou=group,o=xxx"
	searchScope = ldap.SCOPE_SUBTREE
	## retrieve all groupattributes 
	retrieveAttributes = None
	searchFilter = "objectclass=PosixGroup" ##This is the correct objectclass for xxx groups.

	try:
		ldap_result_id = l.search(baseDN, searchScope, searchFilter, retrieveAttributes)
		result_set = []
		while 1:
			result_type, result_data = l.result(ldap_result_id, 0)
			if (result_data == []):
				break
			else:
				if result_type == ldap.RES_SEARCH_ENTRY:
			            result_set.append(result_data)
	    #result_set contains the contents of the ldap query

	except ldap.LDAPError, error:
		return error

	##This will break up the tuple into individual variables based on the supplied key by
	##interrating through the tuples and pulling out the required keys. Use the max function
        ##to find the highest GID and add one to it.
	try:
	    for i in range(len(result_set)):
		for entry in result_set[i]:
		    if entry[1].has_key('gidNumber'):
			gidlist = []
			gidlist.append(entry[1]['gidNumber'][0])
	    output = int(max(gidlist))+1
            return "Next GID = " + str(output)		
            #return "hello" 
	except ValueError:
	    return "Oops! something broke while decoding the LDAP tuples... run!"

    @respond(
        r'''
        .*ldap\snext\suid # show the next available gid
        '''
    )
    def nextuid(self, message, matches):
        """
        Get the next available gid from LDAP 
        """
	ldap_server=os.environ['HUBOT_LDAP_SERVER']
        ldap_username=os.environ['HUBOT_LDAP_USERNAME']
        ldap_password=os.environ['HUBOT_LDAP_PASSWORD']

	try:
	     #Open a connection to the LDAP server.
             l = ldap.open(ldap_server,1389)
	     ## searching doesn't require a bind in LDAP V3.  If you're using LDAP v2, set the next line appropriately
	     ## and do a bind as shown in the above example.
	     # you can also set this to ldap.VERSION2 if you're using a v2 directory
	     # you should  set the next option to ldap.VERSION2 if you're using a v2 directory
             l.protocol_version = ldap.VERSION3	
	     #bind as manager if you need to perform write tasks. Otherwise anonymous will do for a read!
             l.simple_bind_s(ldap_username,ldap_password)
	except ldap.LDAPError, error:
	     return error
             # print the ldap error if something broke.

	## The next lines set the BASEDN and searchscope to only show people, as we want to get the next uid
	baseDN = "ou=people,o=xxx"
	searchScope = ldap.SCOPE_SUBTREE
	## retrieve all groupattributes 
	retrieveAttributes = None
	searchFilter = "objectclass=person" ##This is the correct objectclass for xxx accounts.

	try:
		ldap_result_id = l.search(baseDN, searchScope, searchFilter, retrieveAttributes)
		result_set = []
		while 1:
			result_type, result_data = l.result(ldap_result_id, 0)
			if (result_data == []):
				break
			else:
				if result_type == ldap.RES_SEARCH_ENTRY:
			            result_set.append(result_data)
	    #result_set contains the contents of the ldap query

	except ldap.LDAPError, error:
		return error

	##This will break up the tuple into individual variables based on the supplied key by
	##interrating through the tuples and pulling out the required keys. Use the max function
        ##to find the highest GID and add one to it.
	try:
	    for i in range(len(result_set)):
		for entry in result_set[i]:
		    if entry[1].has_key('uidNumber'):
			uidlist = []
			uidlist.append(entry[1]['uidNumber'][0])
	    output = int(max(uidlist))+1
            return "Next UID = " + str(output)		
            #return "hello" 
	except ValueError:
	    return "Oops! something broke while decoding the LDAP tuples... run!"

    @respond(
            r'''
            .*ldap\screate\sacc\s+ # create an account
            (?P<fn>                  # Parse out firstname
                \S+
            )
            \s+
            (?P<sn>                  # Parse out surname
                \S+
            )
            \s+
            (?P<email>                  # Parse out email
            \S*
            )
	    \s+
            (?P<posixuid>                  # Parse out uid
            \d*
            )
            \s+
            (?P<posixgid>                  # Parse out gid
            \d*
            )
            \s*$
            '''
        )
    def createaccount(self, message, matches):
	fn=matches.group('fn')
        sn=matches.group('sn')
        rawuid=fn[:1]+sn
        uid=rawuid.lower()
	email=matches.group('email')
        posixuid=matches.group('posixuid')
        posixgid=matches.group('posixgid')
        cn = fn+' '+sn
        home = '/home/users/'+uid
        #Debugging regex output
        #output = uid + ' ' + fn + ' ' + sn + ' ' + email + ' ' + posixuid + ' ' + posixgid
        #return output
        ldap_server=os.environ['HUBOT_LDAP_SERVER']
        ldap_username=os.environ['HUBOT_LDAP_USERNAME']
        ldap_password=os.environ['HUBOT_LDAP_PASSWORD']
        try:
            l = ldap.open(ldap_server,1389)
	    l.protocol_version = ldap.VERSION3	
            l.simple_bind_s(ldap_username,ldap_password)
	except ldap.LDAPError, e:
	    return e

	## The next lines will also need to be changed to support your search requirements and directory
	UserDN = "uid="+uid+",ou=people,o=xxx"
	GroupDN = "cn="+uid+",ou=group,o=xxx"

	# Call in a random password
	passwd = self.random_passwd()

	# A dict to help build the "body" of the object
	# Build the user object. Some things coming out of SLACK are in unicode. Use str() to convert to a real string
        userattrs = {}
	userattrs['uid'] = str(uid)
	userattrs['objectclass'] = ['person', 'inetOrgPerson', 'organizationalPerson', 'shadowAccount', 'posixAccount', 'sambaSamAccount', 'top']
	userattrs['loginShell'] = '/bin/tcsh'
	userattrs['uidNumber'] = str(posixuid)
	userattrs['gidNumber'] = str(posixgid)
	userattrs['userPassword'] = passwd
	userattrs['sambaSID'] = 'S-1-5-21-1669545775-1541844246-1604941358-67102'
	userattrs['sn'] = str(sn)
	userattrs['homeDirectory'] = str(home)
	userattrs['mail'] = str(email)
	userattrs['givenName'] = str(fn)
	userattrs['cn'] = str(cn)

	#Build the group object. Some things coming out of SLACK are in unicode. Use str() to convert to a real string
	groupattrs = {}
	groupattrs['cn'] = str(uid)
	groupattrs['objectclass'] = ['groupOfNames', 'posixGroup', 'top']
	groupattrs['gidNumber'] = str(posixgid)

	#covert into a ldif
        userldif = ldap.modlist.addModlist(userattrs)
	groupldif = ldap.modlist.addModlist(groupattrs)

        #write it out to ldap server in sync mode
	l.add_s(UserDN,userldif)
	l.add_s(GroupDN,groupldif)
	l.unbind_s()

	#email user their account details
	#build email
	fromaddr = 'noreply@example.com'
	replyaddr = 'servicedesk@example.com'
	toaddr = email

	msg = MIMEMultipart('alternative')
	msg['From'] = fromaddr
	msg['Reply-to'] = replyaddr
	msg['To'] = email
	msg['Subject'] = "xxx Account Details"

	textbody = "Hi " + str(fn) + "\n\nYour xxx account has been created. The details are as follows: \nUsername: " + str(uid) + " \nPassword: " + passwd + "\n\nKind Regards, \nxxx Systems Team\n"
	message = """Hi {givenname},<br>
        <br>
        Your xxx account has been created. The details are as follows:<br>
	Username: {user}<br>
        Password: {passwd}<br>
        <br>
        Kind Regards,<br> 
        xxx Systems Team<br>
        """

        messagenew = message.format(user=str(uid),email=email,givenname=str(fn),passwd=passwd)

        with open ("/home/hubot/robotics/hubot/node_modules/hubot-python-scripts-2/scripts/xxx-template-start.html", "r") as myfilestart:
                htmlstart = myfilestart.read()

        with open ("/home/hubot/robotics/hubot/node_modules/hubot-python-scripts-2/scripts/xxx-template-end.html", "r") as myfileend:
                htmlend = myfileend.read()

        htmlbody = htmlstart + messagenew + htmlend

        part1 = MIMEText(textbody, 'plain')
        part2 = MIMEText(htmlbody, 'html')
        msg.attach(part1)
        msg.attach(part2)

	#send email
        server = smtplib.SMTP('smtp2.example.com', 25)
        server.ehlo()
        server.ehlo()
        text = msg.as_string()
        server.sendmail(fromaddr, toaddr, text)

        passwd = ""

	return "Account and group created!"

    @respond(
            r'''
            .*ldap\screate\sgrp\s+ # create an account
            (?P<groupname>                  # Parse out firstname
                \S+
            )
            \s+
            (?P<posixgid>                  # Parse out gid
            \d*
            )
            \s*$
            '''
        )

    def creategroup(self, message, matches):
        groupname=matches.group('groupname')
        posixgid=matches.group('posixgid')
        #Debugging regex output
        #output = uid + ' ' + fn + ' ' + sn + ' ' + email + ' ' + posixuid + ' ' + posixgid
        #return output
        ldap_server=os.environ['HUBOT_LDAP_SERVER']
        ldap_username=os.environ['HUBOT_LDAP_USERNAME']
        ldap_password=os.environ['HUBOT_LDAP_PASSWORD']
        try:
            l = ldap.open(ldap_server,1389)
            l.protocol_version = ldap.VERSION3
            l.simple_bind_s(ldap_username,ldap_password)
        except ldap.LDAPError, e:
            return e

        ## The next lines will also need to be changed to support your search requirements and directory
        GroupDN = "cn="+groupname+",ou=group,o=xxx"

        #Build the group object. Some things coming out of SLACK are in unicode. Use str() to convert to a real string
        groupattrs = {}
        groupattrs['cn'] = str(groupname)
        groupattrs['objectclass'] = ['groupOfNames', 'posixGroup', 'top']
        groupattrs['gidNumber'] = str(posixgid)

        #covert into a ldif
        groupldif = ldap.modlist.addModlist(groupattrs)

        #write it out to ldap server in sync mode
        l.add_s(GroupDN,groupldif)
        l.unbind_s()
        return "Group created!"

    @respond(
            r'''
            .*ldap\sgetemail\s+ # create an account
            (?P<uid>                  # Parse out firstname
                \S+
            )
            \s*$
            '''
        )

    def searchuidtoemail(self, message, matches):
        searchuser=matches.group('uid')
        """
        Return the email from uid 
        """
        ldap_server=os.environ['HUBOT_LDAP_SERVER']
        ldap_username=os.environ['HUBOT_LDAP_USERNAME']
        ldap_password=os.environ['HUBOT_LDAP_PASSWORD']

        try:
             #Open a connection to the LDAP server.
             l = ldap.open(ldap_server,1389)
             ## searching doesn't require a bind in LDAP V3.  If you're using LDAP v2, set the next line appropriately
             ## and do a bind as shown in the above example.
             # you can also set this to ldap.VERSION2 if you're using a v2 directory
             # you should  set the next option to ldap.VERSION2 if you're using a v2 directory
             l.protocol_version = ldap.VERSION3
             #bind as manager if you need to perform write tasks. Otherwise anonymous will do for a read!
             l.simple_bind_s(ldap_username,ldap_password)
        except ldap.LDAPError, error:
             return error
             # print the ldap error if something broke.

        ## The next lines set the BASEDN and searchscope to only show people, as we want to get the next uid
        baseDN = "ou=people,o=xxx"
        searchScope = ldap.SCOPE_SUBTREE
        ## retrieve all groupattributes 
        retrieveAttributes = ["mail"]
        searchFilter = "uid="+searchuser ##This is the correct objectclass for xxx accounts.

        try:
                ldap_result_id = l.search(baseDN, searchScope, searchFilter, retrieveAttributes)
                result_set = []
                while 1:
                        result_type, result_data = l.result(ldap_result_id, 0)
                        if (result_data == []):
                                break
                        else:
                                if result_type == ldap.RES_SEARCH_ENTRY:
                                    result_set.append(result_data)
            #result_set contains the contents of the ldap query

        except ldap.LDAPError, error:
                return error
        try:
            for i in range(len(result_set)):
                for entry in result_set[i]:
                    output = entry[1]['mail'][0]
        except ValueError:
	    return "Oops! something broke while decoding the LDAP tuples..."
        return output 

    ## Generate the random password
    def random_passwd(self):
       password = grampg.PasswordGenerator()
       generator = (password.of()
                    .between(3, 7, 'lower_letters')
	            .exactly(5, 'upper_letters')
	            .length(10)
	            .done())
       return generator.generate()
    
    @respond(
            r'''
            .*ldap\sreset\spassword\s+ # reset password
            (?P<uid>                  # for user
                \S+
            )
            \s*$
            '''
        )


    def reset_passwd(self, message, matches):
        username=matches.group('uid')
	
        self.passwd = self.random_passwd()
	ldap_server=os.environ['HUBOT_LDAP_SERVER']
        ldap_username=os.environ['HUBOT_LDAP_USERNAME']
        ldap_password=os.environ['HUBOT_LDAP_PASSWORD']

        try:
             #Open a connection to the LDAP server.
             l = ldap.open(ldap_server,1389)
             ## searching doesn't require a bind in LDAP V3.  If you're using LDAP v2, set the next line appropriately
             ## and do a bind as shown in the above example.
             # you can also set this to ldap.VERSION2 if you're using a v2 directory
             # you should  set the next option to ldap.VERSION2 if you're using a v2 directory
             l.protocol_version = ldap.VERSION3
             #bind as manager if you need to perform write tasks. Otherwise anonymous will do for a read!
             l.simple_bind_s(ldap_username,ldap_password)
        except ldap.LDAPError, error:
             return error
             # print the ldap error if something broke.

	## Base for search
	baseDN = "ou=People,o=xxx"
	searchScope = ldap.SCOPE_SUBTREE
	retrieveAttributes = None
	## User from input
	searchFilter = "uid=%s" % username

	## Confirm user exists
	try:
            ldap_result_id = l.search(baseDN, searchScope, searchFilter, retrieveAttributes)
	    result_set = []
            entries = 0
	    while 1:
	            result_type, result_data = l.result(ldap_result_id, 0)
		    if (result_data == []):
		            break
                    else:
	                    if result_type == ldap.RES_SEARCH_ENTRY:
	                            global dn
		                    dn="uid=%s,%s" % (username,baseDN)
		                    result_set.append(result_data)
			    entries = entries + 1

	except ldap.LDAPError, e:
		print e

	## Get email address from result 
        try:
	    for i in range(len(result_set)):
	            for entry in result_set[i]:
		            global email
		            email=entry[1]['mail'][0]
			    global givenname
                            givenname=entry[1]['givenName'][0]

	except ValueError:
		print "Something is not right.. something is quite wrong!"

	## Build ldif with new password
	old = {'userPassword':'Whatever'}
	new = {'userPassword':self.passwd}
	ldif = modlist.modifyModlist(old,new)

	## Do the actual modification, test for success 
	try:
		l.modify_s(dn,ldif)
	except ldap.LDAPError, e:
		print e

	# Its nice to the server to disconnect and free resources when done
	l.unbind_s()

	## Build the email
	fromaddr = 'noreply@example.com'
	toaddr = email

	msg = MIMEMultipart('alternative')
	msg['From'] = fromaddr
	msg['To'] = email
	msg['Subject'] = "xxx Password Reset"

	textbody = "Hi " + givenname + "\n\nYour password has been reset as follows: \nPassword: " + self.passwd + "\n\nKind Regards, \nxxx Systems Team\n"

	message = """Hi {givenname},<br>
	<br>
	Your password has been reset as follows:<br>
	Password: {passwd}<br>
	<br>
	Kind Regards,<br> 
	xxx Systems Team<br>
	"""

	messagenew = message.format(user=username,email=email,givenname=givenname,passwd=self.passwd)

	with open ("/home/hubot/robotics/hubot/node_modules/hubot-python-scripts-2/scripts/xxx-template-start.html", "r") as myfilestart:
		htmlstart = myfilestart.read()

	with open ("/home/hubot/robotics/hubot/node_modules/hubot-python-scripts-2/scripts/xxx-template-end.html", "r") as myfileend:
		htmlend = myfileend.read()

	htmlbody = htmlstart + messagenew + htmlend

	part1 = MIMEText(textbody, 'plain')
	part2 = MIMEText(htmlbody, 'html')
	msg.attach(part1)
	msg.attach(part2)

	server = smtplib.SMTP('smtp2.example.com', 25)
	server.ehlo()
	server.ehlo()
	text = msg.as_string()
	server.sendmail(fromaddr, toaddr, text)

	self.passwd = ""
	return "Password reset complete, email sent to user"


    @respond(
	    r'''
	    .*ldap\sadd\s+  # add
	    (?P<uid>	    # uid
		\S+
	    )
	    \s+to\sgroup\s+ # to group
	    (?P<group>	    # ldap group
		\S+
	    )
	    \s*$
	    '''
	)

    def add_to_group(self, message, matches):
	username=str(matches.group('uid'))
	ldapgroup=str(matches.group('group'))


	ldap_server=os.environ['HUBOT_LDAP_SERVER']
        ldap_username=os.environ['HUBOT_LDAP_USERNAME']
        ldap_password=os.environ['HUBOT_LDAP_PASSWORD']
	
        ## Open connection to LDAP server
	try:
             l = ldap.open(ldap_server,1389)
             l.protocol_version = ldap.VERSION3
             l.simple_bind_s(ldap_username,ldap_password)
        except ldap.LDAPError, error:
             return error

	## Base for search
	uidbaseDN = "ou=People,o=xxx"
	groupbaseDN = "ou=group,o=xxx"
	searchScope = ldap.SCOPE_SUBTREE
	retrieveAttributes = None
	## Args from input
	uidsearchFilter = "uid=%s" % username
	groupsearchFilter = "cn=%s" % ldapgroup

	## Confirm user exists
	try:
	        ldap_result_id = l.search(uidbaseDN, searchScope, uidsearchFilter, retrieveAttributes)
	        result_type, result_data = l.result(ldap_result_id, 0)
	        if (result_data == []):
		        raise Exception("user %s does not exist" % username)

	except ldap.LDAPError, e:
	        print e

	## Confirm group exists
	try:
	        ldap_result_id = l.search(groupbaseDN, searchScope, groupsearchFilter, retrieveAttributes)
	        result_type, result_data = l.result(ldap_result_id, 0)
	        if (result_data == []):
		        raise Exception("group %s does not exist" % ldapgroup)
	        else:
		        if result_type == ldap.RES_SEARCH_ENTRY:
			           global dn
				   dn="cn=%s,%s" % (ldapgroup,groupbaseDN)

	except ldap.LDAPError, e:
	        print e

	## Add user to group
	old = {}
	new = {'memberUid':username}

	ldif = modlist.modifyModlist(old,new)
	l.modify_s(dn,ldif)

	# Its nice to the server to disconnect and free resources when done
	l.unbind_s()

	return "User %s has been added to group %s" % (username,ldapgroup)


# vim: set shiftwidth=4 softtabstop=4 textwidth=0 wrapmargin=0 syntax=python:
