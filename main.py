import base64
import hashlib
import hmac
import json
import logging
import random
import string
import sys
import time

import math
import requests

WAIT_MINUTES = 5

ROUTE_PREFIX = "api/pro/v1"
ROUTE_PREFIX_V2 = "api/pro/v2"

BTMXCFG = {
    "https": "https://ascendex.com",
    "wss": "wss://ascendex.com:443",
    "group": 6,
    "apikey": "YOUR_KEY",
    "secret": "YOUR_SECRET"
}


def check_sys_version():
    if not sys.version_info >= (3, 5):
        logging.info("Error: Python 3.5+ required")
        sys.exit(1)


def uuid32():
    return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(32))


def utc_timestamp():
    return int(round(time.time() * 1e3))


def sign(msg, secret):
    msg = bytearray(msg.encode("utf-8"))
    hmac_key = base64.b64decode(secret)
    signature = hmac.new(hmac_key, msg, hashlib.sha256)
    signature_b64 = base64.b64encode(signature.digest()).decode("utf-8")
    return signature_b64


def make_auth_headers(timestamp, path, apikey, secret):
    # convert timestamp to string
    if isinstance(timestamp, bytes):
        timestamp = timestamp.decode("utf-8")
    elif isinstance(timestamp, int):
        timestamp = str(timestamp)

    msg = "{}+{}".format(timestamp, path)

    header = {
        "x-auth-key": apikey,
        "x-auth-signature": sign(msg, secret),
        "x-auth-timestamp": timestamp,
    }

    return header


def parse_response(resp_res):
    if resp_res is None:
        return False
    elif resp_res.status_code == 200:
        obj = json.loads(resp_res.text)
        return obj
    else:
        logging.info("request failed, error code = {res.status_code}")
        return False


def gen_server_order_id(user_uid, cl_order_id, ts, order_src='a'):
    return (order_src + format(ts, 'x')[-11:] + user_uid[-11:] + cl_order_id[-9:])[:32]


def initialize_logger():
    logging.basicConfig(level=logging.INFO,
                        format="%(message)s",
                        handlers=[logging.FileHandler("StableBot.log"), logging.StreamHandler()])


class StableBot:

    def __init__(self, budget, min_order_size, coin, base_coin, max_buy_stable_value, min_sell_stable_value):
        # User Setting variables
        self.budget = budget
        self.min_order_size = min_order_size
        self.coin = coin
        self.base_coin = base_coin
        self.stable_pair = '{}/{}'.format(coin, base_coin)
        self.max_buy_stable_value = max_buy_stable_value
        self.min_sell_stable_value = min_sell_stable_value
        # Other useful variables
        self.bought_amount = 0
        self.pending_buy_order = None
        self.pending_sell_order = None
        self.running = True
        self.host = BTMXCFG['https']
        self.group = BTMXCFG['group']
        self.apikey = BTMXCFG['apikey']
        self.secret = BTMXCFG['secret']
        self.coin_balance = None
        self.base_balance = None
        self.orders = []

    def ticker_info(self):
        api_url = "{}/{}/ticker".format(self.host, ROUTE_PREFIX)
        api_params = dict(symbol=self.stable_pair)
        return parse_response(requests.get(api_url, params=api_params))

    def has_pair_open_orders(self):
        ts = utc_timestamp() + 30000
        headers = make_auth_headers(ts, "order/open", self.apikey, self.secret)
        url = "{}/{}/api/pro/v1/cash/order/open".format(self.host, self.group)
        res = requests.get(url, headers=headers)
        logging.info("Order check request: {}".format(res.json()))
        if res is not None and "data" in res.json() and len(res.json()['data']) > 0:
            for order in res.json()['data']:
                if order['symbol'] == self.stable_pair and order['status'] not in ['Filled', 'Cancelled', 'Rejected']:
                    return True
        return False

    def clean_orders(self):
            logging.info("Checking if orders are fulfilled..")
            ts = utc_timestamp() + 30000
            headers = make_auth_headers(ts, "order/hist/current", self.apikey, self.secret)
            url = "{}/{}/api/pro/v1/cash/order/hist/current".format(self.host, self.group)
            res = requests.get(url, headers=headers)
            logging.info("Response order history: {}".format(res.json()))
            filled_ids = []
            if res is not None and "data" in res.json() and len(res.json()['data']) > 0:
                for order in res.json()['data']:
                    if order['symbol'] == self.stable_pair and order['status'] not in ['Filled']:
                        filled_ids.append(order['orderId'])
                # Got filled order ids, removing these orders from our local orders (because filled and no more needed)
                i = len(self.orders) - 1
                while i >= 0:
                    order = self.orders[i]
                    if "order_id" in order:
                        for id_order in filled_ids:
                            if order["order_id"] == id_order:
                                self.orders.pop(i)
                    i = i - 1
            else:
                logging.info("Cannot clean orders with history")

    def check_balance(self, asset):
        ts = utc_timestamp() + 30000
        headers = make_auth_headers(ts, "balance", self.apikey, self.secret)
        params = dict(asset=asset)
        url = "{}/{}/api/pro/v1/cash/balance".format(self.host, self.group)
        res = requests.get(url, headers=headers, params=params)
        logging.info("Balance request: {}".format(res.json()))
        return res is not None \
               and "data" in res.json() \
               and len(res.json()['data']) > 0 \
               and "availableBalance" in res.json()['data'][0] \
               and float(res.json()['data'][0]["availableBalance"]) >= self.budget

    def get_balance(self, asset):
        ts = utc_timestamp() + 30000
        headers = make_auth_headers(ts, "balance", self.apikey, self.secret)
        params = dict(asset=asset)
        url = "{}/{}/api/pro/v1/cash/balance".format(self.host, self.group)
        res = requests.get(url, headers=headers, params=params)
        logging.info("Balance request: {}".format(res.json()))
        if res is not None \
                and "data" in res.json() \
                and len(res.json()['data']) > 0 \
                and "availableBalance" in res.json()['data'][0]:
            return float(res.json()['data'][0]["availableBalance"])
        else:
            return 0

    def place_buy_order(self):
        api_url = "{}/{}/api/pro/v1/cash/order".format(self.host, self.group)
        logging.info("Placing BUY order for {} USDT in {} pair price: {}".format(self.min_order_size,
                                                                                 self.stable_pair,
                                                                                 self.max_buy_stable_value))
        ts = utc_timestamp() + 30000
        order = dict(
            id=uuid32(),
            time=ts,
            symbol=self.stable_pair,
            orderPrice=str(self.max_buy_stable_value),
            orderQty=str(self.min_order_size),
            orderType="limit",
            side="buy"
        )
        headers = make_auth_headers(ts, "order", self.apikey, self.secret)
        res = requests.post(api_url, headers=headers, json=order)
        logging.info("Request response: {}".format(res.json()))

        if res is None or "code" not in res.json() or res.json()['code'] != 0:
            return -1
        else:
            return res.json()['data']['info']['orderId']

    def place_sell_order(self):
            api_url = "{}/{}/api/pro/v1/cash/order".format(self.host, self.group)
            logging.info("Placing SELL order for {} pair.".format(self.stable_pair))
            ts = utc_timestamp() + 30000
            order = dict(
                id=uuid32(),
                time=ts,
                symbol=self.stable_pair,
                orderPrice=str(self.min_sell_stable_value),
                orderQty=str(self.min_order_size),
                orderType="limit",
                side="sell"
            )
            headers = make_auth_headers(ts, "order", self.apikey, self.secret)
            res = requests.post(api_url, headers=headers, json=order)
            logging.info("Request response: {}".format(res.json()))

            if res is None or "code" not in res.json() or res.json()['code'] != 0:
                return -1
            else:
                return res.json()['data']['info']['orderId']

    def split_orders(self):
        # Counting open sell and buy order to remove that amount from the budget
        open_buy_orders = 0
        open_sell_orders = 0
        for order in self.orders:
            if order['type'] == "buy":
                open_buy_orders = open_buy_orders + 1
            else:
                open_sell_orders = open_sell_orders + 1

        # Getting balances from exchange
        self.base_balance = self.get_balance(self.base_coin)
        self.coin_balance = self.get_balance(self.coin)
        if self.base_balance > self.budget - (open_buy_orders * self.min_order_size):
            self.base_balance = self.budget - (open_buy_orders * self.min_order_size)
        if self.coin_balance > self.budget - (open_sell_orders * self.min_order_size):
            self.coin_balance = self.budget - (open_sell_orders * self.min_order_size)
        # Creating order to set
        id_order = len(self.orders) + 1
        i = 0
        while i < math.floor(self.base_balance / self.min_order_size):
            order = {"type" : "buy", "id": id_order}
            self.orders.append(order)
            i = i + 1
            id_order = id_order + 1
        i = 0
        while i < math.floor(self.coin_balance / self.min_order_size):
            order = {"type" : "sell", "id": id_order}
            self.orders.append(order)
            i = i + 1
            id_order = id_order + 1
        new_order = 0
        for order in self.orders:
            if "order_id" not in order:
                new_order = new_order + 1
        if new_order == 0:
            logging.info("Not enough balance to set order")
            return False
        return True

    def run(self):
        logging.info(self.ticker_info())
        while True:
            try:
                self.clean_orders()
                if self.split_orders():
                    # place order
                    for order in self.orders:
                        if "order_id" not in order:
                            if order['type'] == 'buy':
                                order_id = self.place_buy_order()
                                if order_id != -1:
                                    logging.info("Buy order with id {} placed.".format(order_id))
                                    order['order_id'] = order_id
                                else:
                                    logging.info("Error placing buy order.")
                            else:
                                order_id = self.place_sell_order()
                                if order_id != -1:
                                    logging.info("Sell order with id {} placed.".format(order_id))
                                    order['order_id'] = order_id
                                else:
                                    logging.info("Error placing sell order.")
                    # Remove all orders without order_id (not set for any reason)
                    i = len(self.orders) - 1
                    while i >= 0:
                        order = self.orders[i]
                        if "order_id" not in order:
                            self.orders.pop(i)
                        i = i - 1
                logging.info("Current order status: {}\n".format(self.orders))
                logging.info("Execution finished.\nTrying again in {} minutes.".format(WAIT_MINUTES))
                time.sleep(WAIT_MINUTES * 60)
            except Exception as e:
                logging.info("Exception while running bot: {}.\nTrying again in {} minutes.".format(e, WAIT_MINUTES))


if __name__ == '__main__':
    # Configure following variable
    coin = 'XDAI'
    base_coin = 'USDT'
    chosen_budget = 2700
    min_order = 100
    min_price = 0.9958
    max_price = 1.0006
    # From these line below don't touch
    initialize_logger()
    stable_bot = StableBot(chosen_budget, min_order, coin, base_coin, min_price, max_price)
    stable_bot.run()
