"""
Utilities for working with ACS net logs.
"""
from collections import Counter
import csv
from dataclasses import astuple, dataclass
import functools
import logging
from pathlib import Path
import os
import re
import sqlite3
import time
import xml.etree.ElementTree as ET

import requests
import pytest

CALLSIGN_REX = re.compile(r"([A-Z]{1,3}[0-9][A-Z]{1,3})")
QRZ_ENDPOINT_AUTH = "https://xmldata.qrz.com/xml/current/?username={username};password={password};agent=kf7hvm-lookup"
QRZ_ENDPOINT_LOOKUP = (
    "https://xmldata.qrz.com/xml/current/?s={key};callsign={callsign};t={epoch_ms}"
)
QRZ_SESSION_TAG = "{http://xmldata.qrz.com}Session"
QRZ_KEY_TAG = "{http://xmldata.qrz.com}Key"


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class QRZ:
    def __init__(self):
        self._key = None

    @property
    def key(self):
        if self._key is not None:
            return self._key
        auth_resp = requests.get(
            QRZ_ENDPOINT_AUTH.format(
                username=os.environ["QRZ_USERNAME"],
                password=os.environ["QRZ_PASSWORD"],
            )
        )
        auth_resp.raise_for_status()
        root = ET.fromstring(auth_resp.content)
        for session in root.iter(QRZ_SESSION_TAG):
            for key in root.iter(QRZ_KEY_TAG):
                self._key = key.text
                return self._key

    @functools.lru_cache(1024)
    def lookup_callsign(self, callsign):
        lresp = requests.get(
            QRZ_ENDPOINT_LOOKUP.format(
                key=self.key,
                callsign=callsign,
                epoch_ms=int(time.time() * 1000),
            )
        )
        lresp.raise_for_status()
        root = ET.fromstring(lresp.content)
        return {node.tag.partition("}")[2]: node.text for node in root[0]}


@dataclass
class User:
    call: str
    name: str
    city: str

    __table__ = """
        CREATE TABLE IF NOT EXISTS
        users (
            call text primary key,
            name text,
            city text
        );"""


@dataclass
class Checkin:
    call: str
    date: str
    file: str

    __table__ = """
        CREATE TABLE IF NOT EXISTS
        checkins (
            call text,
            date text,
            file text,
            PRIMARY KEY (call, date, file)
        );"""


class NetDB:
    def __init__(self, dbfile):
        self.dbi = sqlite3.connect(dbfile)
        self._init_tables()
        self.qrz = QRZ()

    def _init_tables(self):
        self.dbi.execute(User.__table__)
        self.dbi.execute(Checkin.__table__)
        self.dbi.commit()

    def users(self):
        c = self.dbi.cursor()
        c.execute(
            """
            SELECT call, name, city
            FROM users
            ORDER BY city ASC, call ASC"""
        )
        for row in c.fetchall():
            yield User(*row)

    def callsign(self, v):
        c = self.dbi.cursor()
        c.execute(
            """SELECT call, name, city
               FROM users
               WHERE call = ?
            """,
            (v.upper(),),
        )
        row = c.fetchone()
        if row:
            return User(*row)
        raise LookupError("unknown call {}".format(v.upper()))

    def import_users(self, users):
        params = []
        for u in users:
            if isinstance(u, User):
                params.extend(
                    (
                        u.call.upper(),
                        u.name.capitalize(),
                        u.city.title(),
                    ),
                )
            else:
                params.extend(u)
        self.dbi.execute(
            """INSERT INTO users (call, name, city)
               VALUES {}
               ON CONFLICT(call) DO UPDATE SET
                   name=excluded.name,
                   city=excluded.city;""".format(
                ",".join(["(UPPER(?), ?, ?)"] * len(users)),
            ),
            params,
        )
        self.dbi.commit()

    def import_users_csv(self, csv_path):
        logger.info("Importing users from {}".format(csv_path))
        with csv_path.open() as csvfile:
            self.import_users(tuple(csv.reader(csvfile)))

    def import_checkins(self, callsigns, file):
        if not callsigns:
            logger.warning(
                "Attempted to import file with no checkins: {}".format(file),
            )
            return
        known_users = set(u.call for u in self.users())
        new_users = []
        for callsign in callsigns:
            if callsign.upper() not in known_users:
                new_user = self.qrz.lookup_callsign(callsign)
                if new_user:
                    new_users.append(
                        User(
                            call=new_user["call"],
                            name=new_user["fname"].partition(" ")[0],
                            city=new_user["addr2"],
                        ),
                    )
        if new_users:
            self.import_users(new_users)
        date = file.name.partition("_")[0]
        params = []
        for callsign in callsigns:
            params.extend((callsign, date, file.name))
        self.dbi.execute(
            """INSERT INTO checkins (call, date, file)
               VALUES {}
               ON CONFLICT DO NOTHING""".format(
                ",".join(["(UPPER(?), ?, ?)"] * len(callsigns)),
            ),
            params,
        )
        self.dbi.commit()

    def import_file(self, path):
        seen = set()
        logger.info("Reading callsigns from {}".format(path))
        for line in path.read_text().splitlines():
            if not line:
                continue
            m = CALLSIGN_REX.search(line.upper())
            if not m:
                logger.debug("Rejected line:\t\t{}".format(line))
                continue
            callsign = m.groups()[0]
            if callsign in seen:
                continue
            seen.add(callsign)
        self.import_checkins(seen, path)

    def import_directory(self, root):
        for ch_file in sorted(root.iterdir()):
            try:
                self.import_file(ch_file)
            except (UnicodeDecodeError, OSError):
                logger.info(
                    "Could not read from {}; ignoring.".format(ch_file),
                    exc_info=True,
                )
                continue

    def nets(self):
        c = self.dbi.cursor()
        c.execute(
            """SELECT date, COUNT(call)
               FROM checkins
               GROUP BY date
               ORDER BY date DESC"""
        )
        return c.fetchall()

    def cities_calls_ncheckins(self):
        c = self.dbi.cursor()
        c.execute(
            """SELECT city, checkins.call, name, COUNT(date) as n_checkins, MAX(date) as last
               FROM checkins
               LEFT JOIN users ON checkins.call = users.call
               GROUP BY checkins.call
               ORDER BY city ASC, n_checkins DESC, last DESC, checkins.call ASC"""
        )
        return c.fetchall()


def checkins_all_up(root):
    cc = Counter()
    cf = {}
    for ch_file in sorted(root.iterdir()):
        seen = set()
        try:
            net_data = ch_file.read_text()
        except (UnicodeDecodeError, OSError):
            logger.info(
                "Could not read from {}; ignoring.".format(ch_file),
                exc_info=True,
            )
            continue
        logger.info("Reading callsigns from {}".format(ch_file))
        for line in ch_file.read_text().splitlines():
            if not line:
                continue
            m = CALLSIGN_REX.search(line.upper())
            if not m:
                logger.debug("Rejected line:\t\t{}".format(line))
                continue
            callsign = m.groups()[0]
            if callsign in seen:
                continue
            seen.add(callsign)
            cc[callsign] += 1
            cf.setdefault(callsign, []).append(ch_file.name)
    return cc, cf


class TestAcsNet:
    @pytest.fixture
    def ndb(self, tmp_path):
        d = NetDB(tmp_path / "foo.db")
        d._init_tables()
        return d

    def test_ndb_import_users(self, ndb):
        users = [
            User(*u)
            for u in (
                ("kf7hvm", "masen", "longview"),
                ("wa7rpm", "rick", "rainier"),
                ("kd7uqr", "kie", "silver lake"),
            )
        ]
        users_upper = [User(u.call.upper(), u.name, u.city) for u in users]
        ndb.import_users(users)
        assert users != list(ndb.users())
        # importing the user automatically uppers the callsign
        assert users_upper == list(ndb.users())

    def test_ndb_import_checkins(self, ndb, tmp_path):
        net_file = tmp_path / "2022-05-02_net.txt"
        callsigns = ["kf7hvm", "wa7rpm", "kd7uqr"]
        ndb.import_checkins(callsigns, net_file)
        assert ndb.nets() == [("2022-05-02", 3)]

    def test_ndb_import_directory(self, ndb, tmp_path):
        net_dir = tmp_path / "nets"
        net_dir.mkdir()
        net1 = net_dir / "2022-05-02_net.txt"
        net1.write_text("kf7hvm\nwa7rpm")
        net2 = net_dir / "2022-05-09_net.txt"
        net2.write_text("kf7hvm\nkd7uqr\nwa7rpm")
        net3 = net_dir / "2022-05-16_net.txt"
        net3.write_text("kf7hvm\nwa7rpm")
        ndb.import_directory(net_dir)
        assert ndb.nets() == [("2022-05-16", 2), ("2022-05-09", 3), ("2022-05-02", 2)]
        from pdb import set_trace

        set_trace()


if __name__ == "__main__":
    script_dir = Path(__file__).parent.resolve()
    users_csv = script_dir / "users.csv"
    ndb = NetDB(script_dir / "ndb.db")
    if users_csv.exists():
        ndb.import_users_csv(users_csv)
    ndb.import_directory(script_dir / "logs")
    fmt = "{:<16} {:<7} {:<20} {:<6} {}"
    print(fmt.format("CITY", "CALL", "NAME", "TOTAL", "LAST"))
    with (script_dir / "user_stats.csv").open("w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        for row in ndb.cities_calls_ncheckins():
            print(fmt.format(*(str(c) for c in row)))
            writer.writerow(row)
    with (script_dir / "users.csv").open("w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        for u in ndb.users():
            writer.writerow(astuple(u))
