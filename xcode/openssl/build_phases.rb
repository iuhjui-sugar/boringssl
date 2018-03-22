require 'xcodeproj'

project = Xcodeproj::Project.open(File.dirname(__FILE__) + '/../BoringSSL.xcodeproj')
project.targets.each do |target|
  target.copy_files_build_phases.each do |phase|
    target.remove_from_project
  end
  files_references = target.headers_build_phase.files_references.sort
  files_references.each do |reference|
    relative_path = reference.real_path.relative_path_from(project.path + '../../')
    next if relative_path.to_s.start_with?('include/')
    next if relative_path.to_s.start_with?('xcode/')
    copy_phase_name = "Copy #{relative_path.dirname} Private Headers"
    copy_phase = target.copy_files_build_phases.find { |phase| phase.name == copy_phase_name } ||
      target.new_copy_files_build_phase(copy_phase_name)
    copy_phase.symbol_dst_subfolder_spec = :wrapper
    copy_phase.dst_path = "../$(PRIVATE_HEADERS_FOLDER_PATH)/#{relative_path.dirname}"
    copy_phase.add_file_reference(reference, true)
  end
end
project.save
