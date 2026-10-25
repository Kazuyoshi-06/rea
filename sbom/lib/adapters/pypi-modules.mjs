// Import-module → PyPI distribution names, for the bytecode path only (no dist-info available).
//
// A static table of conventional pairs, deliberately short. The import name of a package is NOT
// its distribution name in general (PyYAML ↔ yaml, Pillow ↔ PIL), and several distributions can
// provide the same module; this table records the common, unambiguous cases and nothing else.
// A module that is not listed stays a module: it is reported as an unknown with its module
// name, never with a guessed distribution name. Identity pairs are listed explicitly for the
// same reason (they are not assumed).
// Not a pairing source of truth: it is looked up by module name only and never validated against
// the artifact. Entries must not map namespace packages (google, azure, ruamel, zope, ...).
export const MODULE_DISTRIBUTIONS = Object.freeze({
  // Identity pairs seen in the corpus and other very common packages
  requests: "requests",
  urllib3: "urllib3",
  certifi: "certifi",
  idna: "idna",
  six: "six",
  click: "click",
  numpy: "numpy",
  pandas: "pandas",
  scipy: "scipy",
  jinja2: "Jinja2",
  markupsafe: "MarkupSafe",
  flask: "Flask",
  werkzeug: "Werkzeug",
  // Import name differs from the distribution name
  charset_normalizer: "charset-normalizer",
  yaml: "PyYAML",
  PIL: "Pillow",
  cv2: "opencv-python",
  sklearn: "scikit-learn",
  skimage: "scikit-image",
  bs4: "beautifulsoup4",
  dateutil: "python-dateutil",
  dotenv: "python-dotenv",
  jwt: "PyJWT",
  OpenSSL: "pyOpenSSL",
  Crypto: "pycryptodome",
  attr: "attrs",
  serial: "pyserial",
  usb: "pyusb",
  git: "GitPython",
  zmq: "pyzmq",
  nacl: "PyNaCl",
  MySQLdb: "mysqlclient",
  gi: "PyGObject",
  wx: "wxPython",
  markdown: "Markdown",
});
