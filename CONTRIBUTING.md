# How to contribute to this project

## Development

To contribute to this package, clone it and install it into a virtual environment:

```bash
$ git clone git@github.com:Styria-Digital/django-rest-framework-jwt.git
$ cd django-rest-framework-jwt.git
$ pip install -e .[dev]
```

The most important dependency is [`tox`](https://tox.readthedocs.io/en/latest/).
It's already listed as a `dev` dependency so it should be installed if the
previous command was run. To check the current `tox` version, type:

```bash
$ pip show tox
```

If it is not installed, type:

```bash
$ pip install tox
```

### Using the demo project

You can use the `demo` project as you would any other Django project by running `$ tox -e serve`.
This creates a separate `tox` environment and executes the `runserver` command using the development settings.
If you want to pass additional arguments, e.g. your custom settings, use the following syntax:

```bash
$ tox -e serve -- --settings=demo.settings.dev-custom
```

## Testing

To run the test suite against current virtual environment run the `pytest` while adding the `demo` and `src` directories to `PYTHONPATH`:

```bash
$ PYTHONPATH=${PYTHONPATH}:./demo:./src/ pytest
```

The whole test suite can be run using [`tox`](https://tox.readthedocs.io/en/latest/):

```bash
$ tox
```

or for a specific environment configuration (with coverage):

```bash
$ tox -e py27-dj111-drf37 -- --cov=rest_framework_jwt
```

## Changelog

This project uses [`towncrier`](https://github.com/hawkowl/towncrier)
for management of changelogs. You don't need to install it yourself since
you'll be using it through `tox`, but please adhere to the following rules:

1. For each pull request, create a new file in the `changelog.d` directory with
    a filename adhering to the `#mr.(feature|bugfix|doc|removal|misc).md`
    schema. For example, `changelog.d/77.bugfix.md` that is submitted in the
    pull request 77. `towncrier` will automatically add a link to the note
    when building the final changelog.
2. Wrap symbols like modules, functions, or classes into backticks so
    they are rendered in a monospace font.
3. If you mention functions or other callables, add parentheses at the end of
    their names: `func()` or `Class.method()`. This makes the changelog a
    lot more readable.

`tox -e changelog -- --draft` will render the current changelog to the terminal
    if you have any doubts.

## Documentation

To build the documentation, run the following command:

```bash
$ tox -e docs
```

To deploy documentation to GitHub run:

```bash
$ mkdocs gh-deploy
```

The documentation should be available in `/html/index.html`.


### Make release and upload to PyPI.org

The CI environment should build packages and upload them to the PyPI server
when a tag is pushed to `origin`. Therefore, if you want to make a new release,
all you have to do is execute the `release` environment in `tox`:

```bash
$ tox -e release
```

This environment will merge the changelogs from the `changelog.d` directory
into [`CHANGELOG.md`](./CHANGELOG.md), bump the **minor** version (by default)
using [bumpversion](https://github.com/peritus/bumpversion), commit the
changes, create a tag and push the changes and the tags to `origin`.

If you want to make a **patch** release, type:

```bash
$ tox -e release -- patch
```

If Travis CI builds were successful release should be automatically uploaded to PyPI.org.
