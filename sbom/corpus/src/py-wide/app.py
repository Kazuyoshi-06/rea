# Experiment (held-out for the bytecode spike): many distributions, none selected by the module table
# except the ones it lists; no metadata embedded.
import attr
import bs4
import click
import colorama
import dateutil.parser
import dotenv
import jinja2
import jwt
import markupsafe
import pyparsing
import pytz
import six
import soupsieve
import toml
import tqdm
import typing_extensions

print(jinja2.Template("{{ x }}").render(x=attr.__name__), click, colorama, dateutil, dotenv, jwt)
print(markupsafe, pyparsing, pytz, six, soupsieve, toml, tqdm, typing_extensions, bs4)
