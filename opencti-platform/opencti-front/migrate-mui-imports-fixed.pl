#!/usr/bin/perl
use strict;
use warnings;

# Hash mapping MUI component names to their components equivalents
my %mui_to_components = (
    'Accordion' => 'Accordion',
    'AccordionDetails' => 'AccordionDetails',
    'AccordionSummary' => 'AccordionSummary',
    'Alert' => 'Alert',
    'AlertTitle' => 'AlertTitle',
    'Autocomplete' => 'Autocomplete',
    'Avatar' => 'Avatar',
    'Badge' => 'Badge',
    'Box' => 'Box',
    'Breadcrumbs' => 'Breadcrumbs',
    'Button' => 'Button',
    'ButtonGroup' => 'ButtonGroup',
    'Card' => 'Card',
    'CardActionArea' => 'CardActionArea',
    'CardActions' => 'CardActions',
    'CardContent' => 'CardContent',
    'CardHeader' => 'CardHeader',
    'Checkbox' => 'Checkbox',
    'Chip' => 'Chip',
    'Collapse' => 'Collapse',
    'Dialog' => 'Dialog',
    'DialogActions' => 'DialogActions',
    'DialogContent' => 'DialogContent',
    'DialogContentText' => 'DialogContentText',
    'DialogTitle' => 'DialogTitle',
    'Divider' => 'Divider',
    'Drawer' => 'Drawer',
    'Fab' => 'Fab',
    'FormControl' => 'FormControl',
    'FormControlLabel' => 'FormControlLabel',
    'FormGroup' => 'FormGroup',
    'FormHelperText' => 'FormHelperText',
    'FormLabel' => 'FormLabel',
    'Grid' => 'Grid',
    'IconButton' => 'IconButton',
    'InputAdornment' => 'InputAdornment',
    'InputLabel' => 'InputLabel',
    'LinearProgress' => 'LinearProgress',
    'List' => 'List',
    'ListItem' => 'ListItem',
    'ListItemButton' => 'ListItemButton',
    'ListItemIcon' => 'ListItemIcon',
    'ListItemText' => 'ListItemText',
    'Menu' => 'Menu',
    'MenuItem' => 'MenuItem',
    'Modal' => 'Modal',
    'Paper' => 'Paper',
    'Popover' => 'Popover',
    'Radio' => 'Radio',
    'Rating' => 'Rating',
    'Select' => 'Select',
    'Skeleton' => 'Skeleton',
    'Slider' => 'Slider',
    'Snackbar' => 'Snackbar',
    'Step' => 'Step',
    'StepButton' => 'StepButton',
    'StepLabel' => 'StepLabel',
    'Stepper' => 'Stepper',
    'Switch' => 'Switch',
    'Tab' => 'Tab',
    'Table' => 'Table',
    'TableBody' => 'TableBody',
    'TableCell' => 'TableCell',
    'TableContainer' => 'TableContainer',
    'TableHead' => 'TableHead',
    'TableRow' => 'TableRow',
    'Tabs' => 'Tabs',
    'TextField' => 'TextField',
    'ToggleButton' => 'ToggleButton',
    'ToggleButtonGroup' => 'ToggleButtonGroup',
    'Tooltip' => 'Tooltip',
    'Typography' => 'Typography'
);

# Constants to avoid interpolation issues
my $COMPONENTS_IMPORT = q{@components};
my $MUI_MATERIAL_IMPORT = q{@mui/material};

# Command line options (simple argument parsing)
my $dry_run = 0;
my $help = 0;

# Parse command line arguments
foreach my $arg (@ARGV) {
    if ($arg eq '--dry-run' || $arg eq '-d') {
        $dry_run = 1;
    } elsif ($arg eq '--help' || $arg eq '-h') {
        $help = 1;
    }
}

if ($help) {
    print <<"EOF";
Usage: $0 [options]

Options:
    --dry-run, -d    Test mode: process only first 10 files without making changes
    --help, -h       Show this help message

Examples:
    perl migrate-mui-imports-fixed.pl --dry-run    # Test with 10 files
    perl migrate-mui-imports-fixed.pl              # Process all files
EOF
    exit 0;
}

# Counter for tracking changes
my $files_processed = 0;
my $files_changed = 0;
my $total_replacements = 0;
my $max_files = $dry_run ? 10 : 0; # 0 means no limit

my $mode_text = $dry_run ? ' (DRY RUN - first 10 files only)' : '';
print 'Starting MUI to ' . $COMPONENTS_IMPORT . ' migration' . $mode_text . '...' . "\n";
print 'Supported components: ' . (scalar keys %mui_to_components) . "\n\n";

# Built-in file operations (no external dependencies)
sub read_file {
    my $filename = shift;
    local $/;
    open my $fh, '<', $filename or die "Could not open $filename: $!";
    my $content = <$fh>;
    close $fh;
    return $content;
}

sub write_file {
    my ($filename, $content) = @_;
    open my $fh, '>', $filename or die "Could not write $filename: $!";
    print $fh $content;
    close $fh;
}

sub min {
    my ($a, $b) = @_;
    return $a < $b ? $a : $b;
}

# Find all relevant files recursively
sub find_files {
    my $dir = shift;
    my @files = ();

    opendir(my $dh, $dir) or return @files;
    my @entries = readdir($dh);
    closedir($dh);

    foreach my $entry (@entries) {
        next if $entry eq '.' or $entry eq '..';
        my $path = "$dir/$entry";

        if (-d $path) {
            # Skip certain directories
            next if $entry =~ /^(node_modules|build|dist|__generated__|\.git)$/;
            push @files, find_files($path);
        } elsif (-f $path && $entry =~ /\.(js|jsx|ts|tsx)$/) {
            push @files, $path;
        }
    }

    return @files;
}

sub process_file {
    my $filepath = shift;

    # Skip if we've reached the file limit (for dry-run)
    if ($max_files > 0 && $files_processed >= $max_files) {
        return;
    }

    $files_processed++;

    # Read file content
    my $content = eval { read_file($filepath) };
    if ($@) {
        warn "Could not read file $filepath: $@";
        return;
    }

    my $original_content = $content;
    my $file_changes = 0;

    # Track components imported from MUI that we can replace
    my @components_to_import = ();
    my %existing_components_import = ();

    # Check if there's already an import from components
    # Using regex with variable substitution to avoid interpolation
    my $components_pattern = qr/import\s+\{([^}]+)\}\s+from\s+['"]$COMPONENTS_IMPORT['"]/;
    if ($content =~ /$components_pattern/) {
        my $existing_imports = $1;
        $existing_imports =~ s/\s//g;
        %existing_components_import = map { $_ => 1 } split /,/, $existing_imports;
    }

    # Process individual MUI component imports
    # Pattern: import ComponentName from 'MUI_MATERIAL_IMPORT/ComponentName'
    my @individual_matches = ();
    my $individual_pattern = qr/import\s+(\w+)\s+from\s+['"]$MUI_MATERIAL_IMPORT\/(\w+)['"];?\s*\n/;

    while ($content =~ /$individual_pattern/g) {
        my $imported_name = $1;
        my $mui_component = $2;
        my $full_match = $&;

        if (exists $mui_to_components{$mui_component}) {
            push @components_to_import, $imported_name unless $existing_components_import{$imported_name};
            push @individual_matches, $full_match;
            $file_changes++;
        }
    }

    # Remove individual MUI imports that we can replace
    foreach my $match (@individual_matches) {
        $content =~ s/\Q$match\E//;
    }

    # Process destructured imports from MUI material
    my @destructured_matches = ();
    my $destructured_pattern = qr/import\s+\{([^}]+)\}\s+from\s+['"]$MUI_MATERIAL_IMPORT['"];?\s*\n/;

    while ($content =~ /$destructured_pattern/g) {
        my $imports_string = $1;
        my $full_match = $&;
        my @imports = split /,/, $imports_string;
        my @remaining_imports = ();

        foreach my $import (@imports) {
            $import =~ s/^\s+|\s+$//g; # trim whitespace

            if (exists $mui_to_components{$import}) {
                push @components_to_import, $import unless $existing_components_import{$import};
                $file_changes++;
            } else {
                push @remaining_imports, $import;
            }
        }

        push @destructured_matches, [$full_match, \@remaining_imports];
    }

    # Replace destructured imports
    foreach my $match_data (@destructured_matches) {
        my ($full_match, $remaining_imports) = @$match_data;

        if (@$remaining_imports) {
            my $remaining_str = join ', ', @$remaining_imports;
            my $replacement = 'import { ' . $remaining_str . ' } from \'' . $MUI_MATERIAL_IMPORT . '\';';
            $content =~ s/\Q$full_match\E/$replacement\n/;
        } else {
            # Remove the entire import line
            $content =~ s/\Q$full_match\E//;
        }
    }

    # Add or update components import if we have components to import
    if (@components_to_import) {
        my @all_components = (keys %existing_components_import, @components_to_import);
        @all_components = sort @all_components;

        my $components_import_line = 'import { ' . join(', ', @all_components) . ' } from \'' . $COMPONENTS_IMPORT . '\';';

        if (%existing_components_import) {
            # Replace existing components import
            my $existing_pattern = qr/import\s+\{[^}]+\}\s+from\s+['"]$COMPONENTS_IMPORT['"];?\s*\n?/;
            $content =~ s/$existing_pattern/$components_import_line\n/;
        } else {
            # Add new components import after existing imports
            # Find the end of the import section
            my $last_import_end = 0;
            my $temp_content = $content;

            while ($temp_content =~ /import\s+.*?from\s+['"][^'"]*['"];?\s*/g) {
                $last_import_end = pos($temp_content);
            }

            if ($last_import_end > 0) {
                # Insert directly after the last import line (no extra newlines)
                my $before_insertion = substr($content, 0, $last_import_end - 1);
                my $after_insertion = substr($content, $last_import_end);

                # Check if we need spacing after the new import
                my $spacing_after = "";
                if ($after_insertion =~ /^\s*[^i\s]/) {
                    # Next line is code (not import), add spacing
                    $spacing_after = "\n";
                }

                $content = $before_insertion . $components_import_line . "\n" . $spacing_after . $after_insertion;
            } else {
                # No imports found, add at beginning with proper spacing
                $content = $components_import_line . "\n\n" . $content;
            }
        }
    }

    # Update counters and write file if changed
    if ($file_changes > 0) {
        $files_changed++;
        $total_replacements += $file_changes;

        if ($dry_run) {
            print "📝 Would update $filepath ($file_changes replacements)\n";
            print "   Preview of changes:\n";
            my @content_lines = split /\n/, $content;
            my @original_lines = split /\n/, $original_content;

            # Show first few lines that would change
            my $preview_lines = 0;
            for my $i (0..min($#content_lines, $#original_lines)) {
                if ($content_lines[$i] ne $original_lines[$i] && $preview_lines < 3) {
                    print "   - $original_lines[$i]\n";
                    print "   + $content_lines[$i]\n";
                    $preview_lines++;
                }
            }
            print "\n";
        } else {
            eval { write_file($filepath, $content) };
            if ($@) {
                warn "Could not write file $filepath: $@";
            } else {
                print "✓ Updated $filepath ($file_changes replacements)\n";
            }
        }
    }
}

# Find and process all files
my @all_files = find_files('./src');
foreach my $file (@all_files) {
    process_file($file);
}

# Print summary
print "\n" . "="x50 . "\n";
if ($dry_run) {
    print "DRY RUN Summary:\n";
} else {
    print "Migration Summary:\n";
}
print "Files processed: $files_processed";
if ($max_files > 0) {
    print " (limited to first $max_files)";
}
print "\n";
print "Files that would be changed: $files_changed\n" if $dry_run;
print "Files changed: $files_changed\n" unless $dry_run;
print "Total replacements: $total_replacements\n";

if ($files_changed > 0) {
    if ($dry_run) {
        print "\n📋 DRY RUN completed!\n";
        print "Run without --dry-run to apply these changes to all files.\n";
    } else {
        print "\n✅ Migration completed successfully!\n";
        print 'All MUI component imports have been replaced with ' . $COMPONENTS_IMPORT . ' imports.' . "\n";
    }
} else {
    print "\nℹ️  No MUI component imports found to migrate.\n";
}

print "\n" . "="x50 . "\n";
