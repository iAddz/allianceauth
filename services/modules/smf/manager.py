from __future__ import unicode_literals
import random
import string
import calendar
from datetime import datetime
import hashlib
import logging
import re
from base64 import b64encode
from Crypto.Cipher import AES
import os

from django.db import connections
from django.conf import settings

from eveonline.models import EveCharacter, EveApiKeyPair #RZR Func

logger = logging.getLogger(__name__)


class SmfManager:
    def __init__(self):
        pass

    SQL_ADD_USER = r"INSERT INTO smf_members (member_name, passwd, email_address, date_registered, real_name," \
                   r" buddy_list, message_labels, openid_uri, signature, ignore_boards) " \
                   r"VALUES (%s, %s, %s, %s, %s, 0, 0, 0, 0, 0)"

    SQL_DEL_USER = r"DELETE FROM smf_members where member_name = %s"

    SQL_DIS_USER = r"UPDATE smf_members SET email_address = %s, passwd = %s WHERE member_name = %s"

    SQL_USER_ID_FROM_USERNAME = r"SELECT id_member from smf_members WHERE member_name = %s"

    SQL_ADD_USER_GROUP = r"UPDATE smf_members SET additional_groups = %s WHERE id_member = %s"

    SQL_GET_GROUP_ID = r"SELECT id_group from smf_membergroups WHERE group_name = %s"

    SQL_ADD_GROUP = r"INSERT INTO smf_membergroups (group_name,description) VALUES (%s,%s)"

    SQL_UPDATE_USER_PASSWORD = r"UPDATE smf_members SET passwd = %s WHERE member_name = %s"

    SQL_REMOVE_USER_GROUP = r"UPDATE smf_members SET additional_groups = %s WHERE id_member = %s"

    SQL_GET_ALL_GROUPS = r"SELECT id_group, group_name FROM smf_membergroups"

    SQL_GET_USER_GROUPS = r"SELECT additional_groups FROM smf_members WHERE id_member = %s"

    SQL_ADD_USER_AVATAR = r"UPDATE smf_members SET avatar = %s WHERE id_member = %s"

    SQL_RZR_ADD_CHAR = r"INSERT INTO smf_rzr_api_member (id_member, memberName, id_corp, id_eve, KeyID, vCode, " \
                       r"api_expire, alt_of, api_state, id_ts3, id_jabber, is_special) " \
                       r"VALUES(%s, %s, %s, %s, %s, %s, %s, %s, 1, 0, 0, 0)"

    SQL_RZR_DEL_CHAR = r"DELETE FROM smf_rzr_api_member WHERE id_member = %s"
    SQL_RZR_DEL_CHAR2 = r"DELETE FROM smf_rzr_api_member WHERE id_eve = %s"
    
    SQL_RZR_DEL_ALTS = r"DELETE FROM smf_rzr_api_member WHERE alt_of IN " \
                       r"(select * from(SELECT id FROM smf_rzr_api_member WHERE id_member= %s) as d)" #Nested again to avoid MySQL Error 1093

    SQL_RZR_GET_MAINID = r"SELECT id FROM smf_rzr_api_member WHERE id_eve= %s"

    @classmethod
    def rzr_getvars(cls, charid, alt):
        character = EveCharacter.objects.get(character_id=charid)
        apikey = EveApiKeyPair.objects.get(api_id=character.api_id)
        evcode = cls.rzr_encrypt(apikey.api_id, apikey.api_key, charid, settings.RZR_SECRET)
        api_expire = (cls.get_current_utc_date())+5259490
        memberid = 0
        if alt==0:
            memberid = cls.get_user_id("[" + character.corporation_ticker + "] " + character.character_name)
        
        results = { 'charname': character.character_name, 'apikey': apikey.api_id, 'evcode': evcode, 
                    'apiexpire': api_expire, 'memberid': memberid, 'corpid': character.corporation_id }
        return results

    @classmethod
    def rzr_getsmfmain_id(cls, charid):
        logger.debug("Getting mainid of evechar %s" % charid)
        
        cursor = connections['smf'].cursor()
        try:
            cursor.execute(cls.SQL_RZR_GET_MAINID, [charid])
            row = cursor.fetchone()
            return row[0]
        except:
            logger.warn("Unable to get RZR smf mainid for evechar %s" % charid)
            pass

    @classmethod
    def rzr_encrypt(cls, apikey, vcode, charid, password):
        salt = hashlib.sha1((apikey + charid).encode('utf-8')).hexdigest()
        key = hashlib.sha256(salt + password).digest()
        iv = os.urandom(16)
        base64_iv = b64encode(iv)
        concatkey = vcode + hashlib.md5(vcode).hexdigest()
        AES.key_size=128
        encryptor=AES.new(key=key,mode=AES.MODE_CBC,IV=iv)
        encoded = b64encode(encryptor.encrypt(concatkey))
        return base64_iv + encoded

    @classmethod
    def rzr_add_all_chars(cls, maincharid):
        user_id = EveCharacter.objects.get(character_id=maincharid).user.id
        main_alliance = EveCharacter.objects.get(character_id=maincharid).alliance_id
        alts = EveCharacter.objects.filter(user_id=user_id, alliance_id=main_alliance).exclude(character_id=maincharid)
        
        member_id = cls.rzr_add_char(maincharid)
        for alt in alts:
            cls.rzr_add_char(alt.character_id, member_id)

    @classmethod
    def rzr_add_char(cls, charid, alt=0):
        rzrvars = cls.rzr_getvars(charid, alt)
        logger.debug("Creating SMF RZR Member %s" % rzrvars['charname'])
        
        cursor = connections['smf'].cursor()
        try:
            cursor.execute(cls.SQL_RZR_ADD_CHAR,
                           [rzrvars['memberid'], rzrvars['charname'], rzrvars['corpid'], charid, 
                           rzrvars['apikey'], rzrvars['evcode'], rzrvars['apiexpire'], alt])
            logger.debug("Created RZR Member %s" % rzrvars['charname'])
            if alt==0:
                return cursor.lastrowid
        except:
            logger.warn("Unable to add RZR smf user %s" % rzrvars['charname'])
            pass

    @classmethod
    def rzr_update_char(cls, charid, alt=0):
        rzrvars = cls.rzr_getvars(charid, alt)
        logger.debug("Update SMF RZR Member %s" % rzrvars['charname'])
        
        cursor = connections['smf'].cursor()
        try:
            cursor.execute(cls.SQL_RZR_UPDATE_CHAR,
                           [rzrvars['charname'], rzrvars['corpid'], charid, rzrvars['apikey'], 
                            rzrvars['evcode'], rzrvars['apiexpire'], alt, charid])
            logger.debug("Updated RZR Member %s" % rzrvars['charname'])
        except:
            logger.warn("Unable to Update RZR smf user %s" % rzrvars['charname'])
            pass

    @classmethod
    def rzr_delete_all_chars(cls, username):
        logger.debug("Deleting SMF RZR Member %s" % username)
        smfid = cls.get_user_id(username)
        cursor = connections['smf'].cursor()
        try:
            cursor.execute(cls.SQL_RZR_DEL_ALTS, [smfid])
            cursor.execute(cls.SQL_RZR_DEL_CHAR, [smfid])
            logger.debug("Deleted RZR Member %s" % username)
        except:
            logger.warn("Unable to Delete RZR smf user %s" % username)
            pass

    @classmethod
    def rzr_del_char(cls, charid):
        logger.debug("Deleting SMF RZR char %s" % charid)
        cursor = connections['smf'].cursor()
        try:
            cursor.execute(cls.SQL_RZR_DEL_CHAR2,
                           [charid])
            logger.debug("Deleted RZR char %s" % charid)
        except:
            logger.warn("Unable to Delete RZR smf char %s" % charid)
            pass

    @staticmethod
    def _sanitize_groupname(name):
        #name = name.strip(' _')
        #return re.sub('[^\w.-]', '', name)
        return name

    @staticmethod
    def generate_random_pass():
        return ''.join([random.choice(string.ascii_letters + string.digits) for n in range(16)])

    @staticmethod
    def gen_hash(username_clean, passwd):
        return hashlib.sha1((username_clean.lower() + passwd).encode('utf-8')).hexdigest()

    @staticmethod
    def santatize_username(username):
        sanatized = username.replace(" ", "_")
        sanatized = sanatized.replace("'", "_")
        return sanatized.lower()

    @staticmethod
    def get_current_utc_date():
        d = datetime.utcnow()
        unixtime = calendar.timegm(d.utctimetuple())
        return unixtime

    @classmethod
    def create_group(cls, groupname):
        logger.debug("Creating smf group %s" % groupname)
        cursor = connections['smf'].cursor()
        cursor.execute(cls.SQL_ADD_GROUP, [groupname, groupname])
        logger.info("Created smf group %s" % groupname)
        return cls.get_group_id(groupname)

    @classmethod
    def get_group_id(cls, groupname):
        logger.debug("Getting smf group id for groupname %s" % groupname)
        cursor = connections['smf'].cursor()
        cursor.execute(cls.SQL_GET_GROUP_ID, [groupname])
        row = cursor.fetchone()
        logger.debug("Got smf group id %s for groupname %s" % (row[0], groupname))
        return row[0]

    @classmethod
    def check_user(cls, username):
        logger.debug("Checking smf username %s" % username)
        cursor = connections['smf'].cursor()
        cursor.execute(cls.SQL_USER_ID_FROM_USERNAME, [username])
        row = cursor.fetchone()
        if row:
            logger.debug("Found user %s on smf" % username)
            return True
        logger.debug("User %s not found on smf" % username)
        return False

    @classmethod
    def add_avatar(cls, member_name, characterid):
        logger.debug("Adding EVE character id %s portrait as smf avatar for user %s" % (characterid, member_name))
        avatar_url = "https://image.eveonline.com/Character/" + characterid + "_64.jpg"
        cursor = connections['smf'].cursor()
        id_member = cls.get_user_id(member_name)
        cursor.execute(cls.SQL_ADD_USER_AVATAR, [avatar_url, id_member])

    @classmethod
    def get_user_id(cls, username):
        logger.debug("Getting smf user id for username %s" % username)
        cursor = connections['smf'].cursor()
        cursor.execute(cls.SQL_USER_ID_FROM_USERNAME, [username])
        row = cursor.fetchone()
        if row is not None:
            logger.debug("Got smf user id %s for username %s" % (row[0], username))
            return row[0]
        else:
            logger.error("username %s not found on smf. Unable to determine user id ." % username)
            return None

    @classmethod
    def get_all_groups(cls):
        logger.debug("Getting all smf groups.")
        cursor = connections['smf'].cursor()
        cursor.execute(cls.SQL_GET_ALL_GROUPS)
        rows = cursor.fetchall()
        out = {}
        for row in rows:
            out[row[1]] = row[0]
        logger.debug("Got smf groups %s" % out)
        return out

    @classmethod
    def get_user_groups(cls, userid):
        logger.debug("Getting smf user id %s groups" % userid)
        cursor = connections['smf'].cursor()
        cursor.execute(cls.SQL_GET_USER_GROUPS, [userid])
        out = [row[0] for row in cursor.fetchall()]
        logger.debug("Got user %s smf groups %s" % (userid, out))
        return out

    @classmethod
    def add_user(cls, username, email_address, groups, characterid):
        logger.debug("Adding smf user with member_name %s, email_address %s, characterid %s" % (
            username, email_address, characterid))
        cursor = connections['smf'].cursor()
        username_clean = username #cls.santatize_username(username) #RZR Naming Conventions
        passwd = cls.generate_random_pass()
        pwhash = cls.gen_hash(username_clean, passwd)
        logger.debug("Proceeding to add smf user %s and pwhash starting with %s" % (username, pwhash[0:5]))
        register_date = cls.get_current_utc_date()
        # check if the username was simply revoked
        if cls.check_user(username_clean) is True:
            logger.warn("Unable to add smf user with username %s - already exists. Updating user instead." % username)
            cls.__update_user_info(username_clean, email_address, pwhash)
            cls.rzr_add_all_chars(characterid)
        else:
            try:
                cursor.execute(cls.SQL_ADD_USER,
                               [username_clean, passwd, email_address, register_date, username_clean])
                cls.add_avatar(username_clean, characterid)
                logger.info("Added smf member_name %s" % username_clean)
                cls.update_groups(username_clean, groups)
                cls.rzr_add_all_chars(characterid)
            except:
                logger.warn("Unable to add smf user %s" % username_clean)
                pass
        return username_clean, passwd

    @classmethod
    def __update_user_info(cls, username, email_address, passwd):
        logger.debug(
            "Updating smf user %s info: username %s password of length %s" % (username, email_address, len(passwd)))
        cursor = connections['smf'].cursor()
        try:
            cursor.execute(cls.SQL_DIS_USER, [email_address, passwd, username])
            logger.info("Updated smf user %s info" % username)
        except:
            logger.exception("Unable to update smf user %s info." % username)
            pass

    @classmethod
    def delete_user(cls, username):
        logger.debug("Deleting smf user %s" % username)
        cursor = connections['smf'].cursor()

        if cls.check_user(username):
            cursor.execute(cls.SQL_DEL_USER, [username])
            logger.info("Deleted smf user %s" % username)
            return True
        logger.error("Unable to delete smf user %s - user not found on smf." % username)
        return False

    @classmethod
    def update_groups(cls, username, groups):
        userid = cls.get_user_id(username)
        logger.debug("Updating smf user %s with id %s groups %s" % (username, userid, groups))
        if userid is not None:
            forum_groups = cls.get_all_groups()
            user_groups = set(cls.get_user_groups(userid))
            act_groups = set([cls._sanitize_groupname(g) for g in groups])
            addgroups = act_groups - user_groups
            remgroups = user_groups - act_groups
            logger.info("Updating smf user %s groups - adding %s, removing %s" % (username, addgroups, remgroups))
            act_group_id = set()
            for g in addgroups:
                if g not in forum_groups:
                    forum_groups[g] = cls.create_group(g)
                act_group_id.add(str(cls.get_group_id(g)))
            string_groups = ','.join(act_group_id)
            cls.add_user_to_group(userid, string_groups)

    @classmethod
    def add_user_to_group(cls, userid, groupid):
        logger.debug("Adding smf user id %s to group id %s" % (userid, groupid))
        try:
            cursor = connections['smf'].cursor()
            cursor.execute(cls.SQL_ADD_USER_GROUP, [groupid, userid])
            logger.info("Added smf user id %s to group id %s" % (userid, groupid))
        except:
            logger.exception("Unable to add smf user id %s to group id %s" % (userid, groupid))
            pass

    @classmethod
    def remove_user_from_group(cls, userid, groupid):
        logger.debug("Removing smf user id %s from group id %s" % (userid, groupid))
        try:
            cursor = connections['smf'].cursor()
            cursor.execute(cls.SQL_REMOVE_USER_GROUP, [groupid, userid])
            logger.info("Removed smf user id %s from group id %s" % (userid, groupid))
        except:
            logger.exception("Unable to remove smf user id %s from group id %s" % (userid, groupid))
            pass

    @classmethod
    def disable_user(cls, username):
        logger.debug("Disabling smf user %s" % username)
        cursor = connections['smf'].cursor()
        password = cls.generate_random_pass()
        revoke_email = "revoked@" + settings.DOMAIN
        try:
            pwhash = cls.gen_hash(username, password)
            cursor.execute(cls.SQL_DIS_USER, [revoke_email, pwhash, username])
            cls.get_user_id(username)
            cls.update_groups(username, [])
            cls.rzr_delete_all_chars(username)
            logger.info("Disabled smf user %s" % username)
            return True
        except TypeError:
            logger.exception("TypeError occured while disabling user %s - failed to disable." % username)
            return False

    @classmethod
    def update_user_password(cls, username, characterid, password=None):
        logger.debug("Updating smf user %s password" % username)
        cursor = connections['smf'].cursor()
        if not password:
            password = cls.generate_random_pass()
        if cls.check_user(username):
            username_clean = username #cls.santatize_username(username) #RZR Naming convention
            pwhash = cls.gen_hash(username_clean, password)
            logger.debug(
                "Proceeding to update smf user %s password with pwhash starting with %s" % (username, pwhash[0:5]))
            cursor.execute(cls.SQL_UPDATE_USER_PASSWORD, [pwhash, username])
            cls.add_avatar(username, characterid)
            logger.info("Updated smf user %s password." % username)
            return password
        logger.error("Unable to update smf user %s password - user not found on smf." % username)
        return ""
