# -*- coding: utf-8 -*-
"""Parser for exim4 formatted log files"""
import re

import pyparsing

from plaso.containers import text_events
from plaso.lib import errors
from plaso.lib import timelib
from plaso.parsers import manager
from plaso.parsers import text_parser


class Exim4LineEvent(text_events.TextEvent):
  """Convenience class for a exim4 line event."""
  DATA_TYPE = u'exim4:line'


class Exim4Parser(text_parser.PyparsingSingleLineTextParser):
  """Parses exim4 formatted log files"""
  NAME = u'exim4'

  DESCRIPTION = u'Exim4 Parser'

  _ENCODING = u'utf-8'

  _VERIFICATION_REGEX = re.compile(r'^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\s')

  _plugin_classes = {}

  # The reporter and facility fields can contain any printable character, but
  # to allow for processing of syslog formats that delimit the reporter and
  # facility with printable characters, we remove certain common delimiters
  # from the set of printable characters.
  _REPORTER_CHARACTERS = u''.join(
      [c for c in pyparsing.printables if c not in [u':', u'[', u'<']])
  _FACILITY_CHARACTERS = u''.join(
      [c for c in pyparsing.printables if c not in [u':', u'>']])

  _PYPARSING_COMPONENTS = {
      u'year': text_parser.PyparsingConstants.YEAR.setResultsName(
          u'year'),
      u'month': text_parser.PyparsingConstants.TWO_DIGITS.setResultsName(
          u'month'),
      u'day': text_parser.PyparsingConstants.TWO_DIGITS.setResultsName(
          u'day'),
      u'hour': text_parser.PyparsingConstants.TWO_DIGITS.setResultsName(
          u'hour'),
      u'minute': text_parser.PyparsingConstants.TWO_DIGITS.setResultsName(
          u'minute'),
      u'second': text_parser.PyparsingConstants.TWO_DIGITS.setResultsName(
          u'second'),
      u'body': pyparsing.Regex(
          r'.*?(?=($|\n\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}))', re.DOTALL).
               setResultsName(u'body')
  }

  _PYPARSING_COMPONENTS[u'date'] = (
      _PYPARSING_COMPONENTS[u'year'] + pyparsing.Suppress(u'-') +
      _PYPARSING_COMPONENTS[u'month'] + pyparsing.Suppress(u'-') +
      _PYPARSING_COMPONENTS[u'day'] +
      _PYPARSING_COMPONENTS[u'hour'] + pyparsing.Suppress(u':') +
      _PYPARSING_COMPONENTS[u'minute'] + pyparsing.Suppress(u':') +
      _PYPARSING_COMPONENTS[u'second'])

  _EXIM4_LINE = (
      _PYPARSING_COMPONENTS[u'date'] +
      pyparsing.Optional(pyparsing.Suppress(u':')) +
      _PYPARSING_COMPONENTS[u'body'] + pyparsing.lineEnd())

  LINE_STRUCTURES = [
      (u'exim4_line', _EXIM4_LINE)]

  _SUPPORTED_KEYS = frozenset([key for key, _ in LINE_STRUCTURES])

  def __init__(self):
    """Initializes a parser object."""
    super(Exim4Parser, self).__init__()
    self._last_month = 0
    self._maximum_year = 0
    self._plugin_objects_by_reporter = {}
    self._year_use = 0

  def EnablePlugins(self, plugin_includes):
    """Enables parser plugins.

    Args:
      plugin_includes (list[str]): names of the plugins to enable, where None
          or an empty list represents all plugins. Note that the default plugin
          is handled separately.
    """
    super(Exim4Parser, self).EnablePlugins(plugin_includes)

    self._plugin_objects_by_reporter = {}
    for plugin_object in self._plugin_objects:
      self._plugin_objects_by_reporter[plugin_object.REPORTER] = plugin_object

  def ParseRecord(self, mediator, key, structure):
    """Parses a matching entry.

    Args:
      mediator (ParserMediator): mediates the interactions between
          parsers and other components, such as storage and abort signals.
      key (str): name of the parsed structure.
      structure (pyparsing.ParseResults): elements parsed from the file.

    Raises:
      UnableToParseFile: if an unsupported key is provided.
    """
    if key not in self._SUPPORTED_KEYS:
      raise errors.UnableToParseFile(u'Unsupported key: {0:s}'.format(key))

    timestamp = timelib.Timestamp.FromTimeParts(
        year=structure.year, month=structure.month, day=structure.day,
        hour=structure.hour, minutes=structure.minute,
        seconds=structure.second, timezone=mediator.timezone)

    reporter = structure.reporter
    attributes = {
        u'body': structure.body}

    plugin_object = self._plugin_objects_by_reporter.get(reporter, None)
    if not plugin_object:
      event_object = Exim4LineEvent(timestamp, 0, attributes)
      mediator.ProduceEvent(event_object)

    else:
      try:
        plugin_object.Process(mediator, timestamp, attributes)

      except errors.WrongPlugin:
        event_object = Exim4LineEvent(timestamp, 0, attributes)
        mediator.ProduceEvent(event_object)

  def VerifyStructure(self, unused_mediator, line):
    """Verifies that this is a exim4-formatted file.

    Args:
      mediator (ParserMediator): mediates the interactions between
          parsers and other components, such as storage and abort signals.
      line (str): single line from the text file.

    Returns:
      bool: whether the line appears to contain syslog content.
    """
    return re.match(self._VERIFICATION_REGEX, line) is not None


manager.ParsersManager.RegisterParser(Exim4Parser)
