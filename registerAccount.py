import re
from urllib.parse import urlparse, parse_qs, unquote
import secrets
import requests
import json
import sys
import gzip
from Crypto.Protocol.KDF import PBKDF2
import pyaes
import hmac
import hashlib
import base64

APP_NAME = "com.amazon.rabbit"
APP_VERSION = "3681690"
DEVICE_NAME = "Le X522"
MANUFACTURER = "LeMobile"
OS_VERSION = "LeEco/Le2_NA/le_s2_na:6.0.1/IFXNAOP5801910272S/61:user/release-keys"




class FlexUnlimited:
  allHeaders = {
    "AmazonApiRequest": {
      "x-amzn-identity-auth-domain": "api.amazon.com",
      "User-Agent": "AmazonWebView/Amazon Flex/0.0/iOS/15.2/iPhone"
    },
    "FlexCapacityRequest": {
      "Accept": "application/json",
      "x-amz-access-token": None,
      "Authorization": "RABBIT3-HMAC-SHA256 SignedHeaders=x-amz-access-token;x-amz-date, "
                       "Signature=82e65bd06035d5bba38c733ac9c48559c52c7574fb7fa1d37178e83c712483c0",
      "X-Amz-Date": None,
      "Accept-Encoding": "gzip, deflate, br",
      "x-flex-instance-id": "BEEBE19A-FF23-47C5-B1D2-21507C831580",
      "Accept-Language": "en-US",
      "Content-Type": "application/json",
      "User-Agent": "iOS/16.1 (iPhone Darwin) Model/iPhone Platform/iPhone14,2 RabbitiOS/2.112.2",
      "Connection": "keep-alive",
      "Cookie": 'session-id=147-7403990-6925948; session-id-time=2082787201l; '
                'session-token=1mGSyTQU1jEQgpSB8uEn6FFHZ1iBcFpe9V7LTPGa3GV3sWf4bgscBoRKGmZb3TQICu7PSK5q23y3o4zYYhP'
                '/BNB5kHAfMvWcqFPv/0AV7dI7desGjE78ZIh+N9Jv0KV8c3H/Xyh0OOhftvJQ5eASleRuTG5+TQIZxJRMJRp84H5Z+YI'
                '+IhWErPdxUVu8ztJiHaxn05esQRqnP83ZPxwNhA4uwaxrT2Xm; '
                'at-main="Atza|IwEBIB4i78dwxnHVELVFRFxlWdNNXzFreM2pXeOHsic9Xo54CXhW0m5juyNgKyCL6KT_9bHrQP7VUAIkxw'
                '-nT2JH12KlOuYp6nbdv-y6cDbV5kjPhvFntPyvBEYcl405QleSzBtH_HUkMtXcxeFYygt8l-KlUA8-JfEKHGD14'
                '-oluobSCd2UdlfRNROpfRJkICzo5NSijF6hXG4Ta3wjX56bkE9X014ZnVpeD5uSi8pGrLhBB85o4PKh55ELQh0fwuGIJyBcyWSpGPZb5'
                'uVODSsXQXogw7HCFEoRnZYSvR_t7GF5hm_78TluPKUoYzvw4EVfJzU"; '
                'sess-at-main="jONjae0aLTmT+yqJV5QC+PC1yiAdolAm4zRrUlcnufM="; '
                'ubid-main=131-1001797-1551209; '
                'x-main="ur180BSwQksvu@cBWH@IQejqHw6ZYkMDKkwbdOwJvEeVZWlh15tnxZdleqfq9qO0"'
    }
  }
  routes = {
    "GetOffers": "https://flex-capacity-na.amazon.com/GetOffersForProviderPost",
    "AcceptOffer": "https://flex-capacity-na.amazon.com/AcceptOffer",
    "GetAuthToken": "https://api.amazon.com/auth/register",
    "RequestNewAccessToken": "https://api.amazon.com/auth/token",
    "ForfeitOffer": "https://flex-capacity-na.amazon.com/schedule/blocks/",
    "GetEligibleServiceAreas": "https://flex-capacity-na.amazon.com/eligibleServiceAreas",
    "GetOfferFiltersOptions": "https://flex-capacity-na.amazon.com/getOfferFiltersOptions"
    }


  def __init__(self) -> None:
        self.session = requests.Session()
        self.accessToken = ""
        self.refreshToken = ""

  def __generate_frc(self, device_id):
        ip_address = requests.get('https://api.ipify.org').text
        cookies = json.dumps({
            "ApplicationName": APP_NAME,
            "ApplicationVersion": APP_VERSION,
            "DeviceLanguage": "en",
            "DeviceName": DEVICE_NAME,
            "DeviceOSVersion": OS_VERSION,
            "IpAddress": ip_address,
            "ScreenHeightPixels": "1920",
            "ScreenWidthPixels": "1280",
            "TimeZone": "00:00",
        })
        compressed = gzip.compress(cookies.encode())
        key = PBKDF2(device_id, b"AES/CBC/PKCS7Padding", dkLen=32)
        iv = secrets.token_bytes(16)
        encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key, iv=iv))
        ciphertext = encrypter.feed(compressed)
        ciphertext += encrypter.feed()
        hmac_ = hmac.new(PBKDF2(device_id, b"HmacSHA256", dkLen=32), iv + ciphertext, hashlib.sha256).digest()
        return base64.b64encode(b"\0" + hmac_[:8] + iv + ciphertext).decode()

  def registerAccount(self, maplanding_url):
        parsed_query = parse_qs(urlparse(maplanding_url).query)
        reg_access_token = unquote(parsed_query['openid.oa2.access_token'][0])
        device_id = secrets.token_hex(16)
        amazon_reg_data = {
            "auth_data": {
                "access_token": reg_access_token
            },
      "cookies": {
        "domain": ".amazon.com",
        "website_cookies": []
      },
      "device_metadata": {
        "android_id": "52aee8aecab31ee3",
        "device_os_family": "android",
        "device_serial": device_id,
        "device_type": "A1MPSLFC7L5AFK",
        "mac_address": secrets.token_hex(64).upper(),
        "manufacturer": MANUFACTURER,
        "model": DEVICE_NAME,
        "os_version": "30",
        "product": DEVICE_NAME
      },
      "registration_data": {
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "device_model": DEVICE_NAME,
        "device_serial": device_id,
        "device_type": "A1MPSLFC7L5AFK",
        "domain": "Device",
        "os_version": OS_VERSION,
        "software_version": "130050002"
      },
      "requested_extensions": [
        "device_info",
        "customer_info"
      ],
      "requested_token_type": [
        "bearer",
        "mac_dms",
        "store_authentication_cookie",
        "website_cookies"
      ],
      "user_context_map": {
        "frc": self.__generate_frc(device_id)
      }
    }

        reg_headers = {
            "Content-Type": "application/json",
            "Accept-Charset": "utf-8",
            "x-amzn-identity-auth-domain": "api.amazon.com",
            "Connection": "keep-alive",
            "Accept": "*/*",
            "Accept-Language": "en-US"
        }
        res = self.session.post(FlexUnlimited.routes.get("GetAuthToken"), json=amazon_reg_data, headers=reg_headers, verify=True)
        if res.status_code != 200:
            return "Login failed."
        res = res.json()
        tokens = res['response']['success']['tokens']['bearer']
        self.accessToken = tokens['access_token']
        self.refreshToken = tokens['refresh_token']
        try:
            with open("config.json", "r+") as configFile:
                config = json.load(configFile)
                config["accessToken"] = self.accessToken
                config["refreshToken"] = self.refreshToken
                configFile.seek(0)
                json.dump(config, configFile, indent=2)
                configFile.truncate()
        except KeyError as nullKey:
            print(f'{nullKey} was not set. Please setup FlexUnlimited as described in the README.')
            sys.exit()
        except FileNotFoundError:
            print("Config file not found. Ensure a properly formatted 'config.json' file exists in the root directory.")
            sys.exit()
        return "Registration successful."

  def extract_tokens_from_url(self, url):
        access_token = re.findall(r'access_token=([\w-]+)', url)
        refresh_token = re.findall(r'refresh_token=([\w-]+)', url)
        return access_token, refresh_token
