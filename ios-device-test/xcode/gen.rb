# Generates an Xcode project that links the KSafe iosArm64 framework into a unit-test
# target, so the curated Swift XCTest cases in Tests/ run on a physical device.
# Driven by env vars set by ../run-xctest.sh (no hardcoded machine paths).
require 'xcodeproj'

ROOT      = File.expand_path(File.dirname(__FILE__))
TEAM      = ENV.fetch('DEVELOPMENT_TEAM')                 # e.g. 36EL4K6NG5
FRAMEWORK = ENV.fetch('KSAFE_FRAMEWORK')                  # …/iosArm64/debugFramework/ksafe.framework
BUNDLE_ID = ENV.fetch('BUNDLE_ID', 'eu.anifantakis.ksafedevtest')
DEPLOY    = '15.0'

proj_path = File.join(ROOT, 'KSafeDeviceTest.xcodeproj')
project   = Xcodeproj::Project.new(proj_path)

host = project.new_target(:application, 'Host', :ios, DEPLOY)
host.add_file_references([project.new_group('Host', 'Host').new_reference(File.join(ROOT, 'Host', 'AppDelegate.swift'))])

tests = project.new_target(:unit_test_bundle, 'KSafeDeviceTests', :ios, DEPLOY)
tests.add_file_references([project.new_group('Tests', 'Tests').new_reference(File.join(ROOT, 'Tests', 'KSafeDeviceTests.swift'))])
tests.add_dependency(host)

fw_ref = project.new_group('Frameworks').new_reference(FRAMEWORK)
fw_ref.source_tree = 'ABSOLUTE'
tests.frameworks_build_phase.add_file_reference(fw_ref)

common = {
  'DEVELOPMENT_TEAM' => TEAM, 'CODE_SIGN_STYLE' => 'Automatic', 'SWIFT_VERSION' => '5.0',
  'IPHONEOS_DEPLOYMENT_TARGET' => DEPLOY, 'TARGETED_DEVICE_FAMILY' => '1,2',
  'GENERATE_INFOPLIST_FILE' => 'YES', 'MARKETING_VERSION' => '1.0', 'CURRENT_PROJECT_VERSION' => '1',
}
host.build_configurations.each do |c|
  c.build_settings.merge!(common)
  c.build_settings['PRODUCT_BUNDLE_IDENTIFIER'] = "#{BUNDLE_ID}.host"
  c.build_settings['INFOPLIST_KEY_UILaunchScreen_Generation'] = 'YES'
end
tests.build_configurations.each do |c|
  c.build_settings.merge!(common)
  c.build_settings['PRODUCT_BUNDLE_IDENTIFIER'] = "#{BUNDLE_ID}.tests"
  c.build_settings['TEST_HOST'] = '$(BUILT_PRODUCTS_DIR)/Host.app/$(BUNDLE_EXECUTABLE_FOLDER_PATH)/Host'
  c.build_settings['BUNDLE_LOADER'] = '$(TEST_HOST)'
  c.build_settings['FRAMEWORK_SEARCH_PATHS'] = ['$(inherited)', File.dirname(FRAMEWORK)]
  c.build_settings['OTHER_LDFLAGS'] = ['$(inherited)', '-framework', 'ksafe']
end

project.save

scheme = Xcodeproj::XCScheme.new
scheme.add_build_target(host)
scheme.add_test_target(tests)
scheme.set_launch_target(host)
scheme.save_as(proj_path, 'KSafeDeviceTests', true)
puts "Generated #{proj_path} (team #{TEAM})"
