"""Synthetic OpenKore declarations; no session data or Perl execution."""
import sys
from pathlib import Path
import tempfile
import unittest
import warnings

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from research.cipher.packet_semantics import load_semantics, SemanticsWarning


class PacketSemanticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, text):
        path = self.root / (name.replace('::', '/') + '.pm')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def test_inheritance_override_comments_and_provenance(self):
        self.write('Network::Base', """package Network::Base;
$self->{packet_list} = {
 '0001' => ['base', 'V', [qw(value)]],
 # '0002' => ['commented'],
 '0003' => ['keep#literal'],
 '0004' => ['multiline',
              'v C', [qw(first second)]],
};
""")
        self.write('Network::Child', """use base qw(Network::Base);
my %packets = (
 '0001' => ['child', 'a4', ['target']], # override
 '0005' => ['added'],
);
$self->{packet_list}{$_} = $packets{$_} for keys %packets;
$self->{packet_list}{'0006'} = ['direct', 'C', [qw(flag)]];
""")
        result = load_semantics(self.root, 'Network::Child')
        self.assertEqual(set(result), {1, 3, 4, 5, 6})
        self.assertEqual(result[1], dict(handler='child', pack='a4', fields=['target'], source_path='Network/Child.pm', source_line=3))
        self.assertEqual(result[3]['handler'], 'keep#literal')
        self.assertEqual(result[4]['fields'], ['first', 'second'])
        self.assertEqual(result[4]['source_line'], 6)
        self.assertEqual(result[5]['pack'], '')
        self.assertEqual(result[6]['fields'], ['flag'])
        self.assertNotIn(0xFFFF, result)

    def test_dynamic_override_is_omitted(self):
        self.write('Base', "$self->{packet_list} = {'0001' => ['base']};")
        self.write('Child', """use base 'Base';
$self->{packet_list}{'0001'} = [$handler, 'V', [qw(field)]];
$self->{packet_list}{'0002'} = make_packet();
$self->{packet_list}{'0003'} = ["$dynamic"];
$self->{packet_list}{'0004'} = ['safe'] . $suffix;
""")
        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter('always', SemanticsWarning)
            self.assertEqual(load_semantics(self.root, 'Child'), {})
        self.assertEqual(len(recorded), 4)
        self.assertTrue(all(item.category is SemanticsWarning for item in recorded))

    def test_unrelated_hash_and_pod_are_ignored(self):
        self.write('Empty', """=pod
$self->{packet_list} = {'0001' => ['documentation']};
=cut
my %unrelated = ('0002' => ['irrelevant']);
my %packets = ('0003' => ['not copied']);
""")
        self.assertEqual(load_semantics(self.root, 'Empty'), {})

    def test_missing_cycle_and_invalid_names(self):
        with self.assertRaises(FileNotFoundError):
            load_semantics(self.root, 'Missing')
        with self.assertRaises(ValueError):
            load_semantics(self.root, '../outside')
        self.write('A', 'use base qw(B);')
        self.write('B', 'use base "A";')
        with self.assertRaisesRegex(ValueError, 'cycle'):
            load_semantics(self.root, 'A')

    def test_literal_length_ternary(self):
        self.write('Conditional', """$self->{packet_list} = {
 '01D7' => ($rpackets{'01D7'}{length} == 15) # or 11
   ? ['sprite_change', 'a4 C V2', [qw(ID type value1 value2)]] # true
   : ['sprite_change', 'a4 C v2', [qw(ID type value1 value2)]] # false
 ,
};""")
        for length, expected in ((15, 'a4 C V2'), (11, 'a4 C v2')):
            with self.subTest(length=length):
                result = load_semantics(self.root, 'Conditional', {0x01D7: length})
                self.assertEqual(result[0x01D7]['pack'], expected)
                self.assertEqual(result[0x01D7]['source_line'], 2)
                self.assertEqual(result[0x01D7]['fields'], ['ID', 'type', 'value1', 'value2'])
        for lengths in (None, {}, {0x01D7: '15'}):
            with self.subTest(lengths=lengths), self.assertWarns(SemanticsWarning):
                self.assertEqual(load_semantics(self.root, 'Conditional', lengths), {})

    def test_unsupported_condition_stays_omitted(self):
        self.write('Conditional', """$self->{packet_list} = {
 '01D7' => ($rpackets{'01D7'}{length} > 11) ? ['yes'] : ['no'],
 '01D8' => ($rpackets{'01D7'}{length} == 15) ? ['yes'] : ['no'],
};""")
        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter('always', SemanticsWarning)
            result = load_semantics(self.root, 'Conditional', {0x01D7: 15, 0x01D8: 15})
        self.assertEqual(result, {})
        self.assertEqual(len(recorded), 2)

    def test_missing_external_base_is_explicit(self):
        self.write("Child", "use base qw(Exporter); $self->{packet_list} = {'0001' => ['local']};")
        with self.assertWarnsRegex(SemanticsWarning, "unresolved base Exporter"):
            result = load_semantics(self.root, "Child")
        self.assertEqual(result[1]["handler"], "local")

    def test_multiple_bases_leftmost_wins(self):
        self.write('Left', "$self->{packet_list} = {'0001' => ['left']};")
        self.write('Right', "$self->{packet_list} = {'0001' => ['right'], '0002' => ['right_only']};")
        self.write('Child', 'use base qw(Left Right);')
        result = load_semantics(self.root, 'Child')
        self.assertEqual(result[1]['handler'], 'left')
        self.assertEqual(result[2]['handler'], 'right_only')


if __name__ == '__main__':
    unittest.main()
