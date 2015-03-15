#!/usr/bin/env ruby
#
#  Motivation:
#  Enigmail is not able to manipulate the mails stored inside thunderbird.
#  Since the mails are only encrypted when viewed via enigmail,
#  there is no way to search through them.
#
#
#  Enigstore - Reads thunderbird mbox files.
#              Writes a copy of that mbox file.
#              For each gpg encrypted message that is found,
#              it inserts a decrypted version of that message below
#              the original one.
#
#  There is no support for netsted mails yet. Please send a test case or money.
#  There is no support for encrypted attachements.
#  They aren't searchable anyway..
#
#  Please be aware that this is one of those 'works for me' solutions.
#  Use with caution! Do not trust me! Read the source!
#  This program could erase everything! ;)
#  Make backups! Have fun!
#
#
#  Prerequisites:
#  Tested with ruby 2.1.5
#  You need to install the ruby mail gem:
#  $ gem install mail
#
#  Usage:
#  Shut down thunderbird
#  $ ruby enigstore.rb <input_file> <your_pass_phrase>
#  (that will leak your passphrase into $unwanted_places!
#   no gpg-agent support yet)
#
#  Example:
#  $ ruby enigstore.rb /full/path/some_mbox_file "my passphrase is not here"
#  will create: /full/path/some_mbox_file-decrypted
#
#
#
#
#  Copyright (C) 2015, Sven Tantau <sven@beastiebytes.com>
#
#  Permission is hereby granted, free of charge, to any person obtaining
#  a copy of this software and associated documentation files (the
#  "Software"), to deal in the Software without restriction, including
#  without limitation the rights to use, copy, modify, merge, publish,
#  distribute, sublicense, and/or sell copies of the Software, and to
#  permit persons to whom the Software is furnished to do so, subject to
#  the following conditions:
#
#  The above copyright notice and this permission notice shall be
#  included in all copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
#  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
#  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
#   IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
#  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
#  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
#  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
#
require 'securerandom'
require 'fileutils'
require 'mail'

class Enigstore
  def self.process_message_buffer(message_buffer, f)
    if message_buffer.join.to_s.include? '-----BEGIN PGP MESSAGE-----'
      new_mail = Enigstore.new.create_mail(Mail.new(message_buffer.join))
      # write new mail into file
      f.write(message_buffer.first)
      new_mail.to_s.split("\n").each do |l|
        f.write(l)
      end
      f.write("\r\n")
    end
  end

  def get_decrypted_message(part)
    decrypt_success = false
    out = []
    out_buffer = []
    start_gpg_found = false
    stop_gpg_found = false
    gpg_buffer = []

    if part.class == Mail::Message
      message = part.header.to_s + "\r\n" + part.decoded
    else # Mail::Part
      message = part.header.to_s + '' + part.decoded
    end

    message_buffer = message.split("\n")
    message_buffer.each do |line|
      # strip/ignore wrong?! gpg headers..
      next if line.start_with?('Charset: ') && start_gpg_found

      if !start_gpg_found and !line.start_with? '-----BEGIN PGP MESSAGE-----'
        out_buffer << line
      end

      if start_gpg_found && !stop_gpg_found
        gpg_buffer << line
      end

      if line.start_with? '-----BEGIN PGP MESSAGE-----'
        start_gpg_found = true
        stop_gpg_found = false
        gpg_buffer << line
      end

      if line.start_with? '-----END PGP MESSAGE-----'
        stop_gpg_found = true
        start_gpg_found = false
        begin
          # puts gpg_buffer.join("\n")
          filename = SecureRandom.hex(16)
          filename_gpg = filename + '.gpg'
          f = File.open(filename_gpg, 'w')
          gpg_buffer.each do |gpg_line|
            f.write(gpg_line + "\n")
          end
          f.close
          cmd = system("echo '#{PASSPHRASE}'|gpg --batch --passphrase-fd 0 --decrypt-file #{filename_gpg}")
          if cmd
            decrypt_success = true
          end
          File.open(filename, 'r').each do |cleartext_line|
            if cleartext_line.start_with? 'From ' # fixme.. cover >From , >>From etc
              cleartext_line = '>' + cleartext_line
            end
            out_buffer << cleartext_line
          end
          FileUtils.rm(filename)
          FileUtils.rm(filename_gpg)
        rescue Exception => e
          puts 'ERROR'
        end
        gpg_buffer = []
      end
    end # loop

    out = out_buffer.join

    [out, decrypt_success]
  end

  def create_mail(mail)
    if mail.multipart?

      mail.parts.each do |part|
        if part.multipart?
          fail 'NYI, no testcase available'
        else
          next unless part.to_s.include? '-----BEGIN PGP MESSAGE-----'

          output, success = get_decrypted_message(part)

          if success
            mail.parts.delete(part)
            new_part = Mail::Part.new(output)
            mail.parts << new_part
          end

        end
      end # mail.parts
      # fix header
      mail.header = mail.header.to_s.gsub('multipart/encrypted', 'multipart/mixed')
      return mail

    else        # no multipart
      output, success = get_decrypted_message(mail)
      return Mail.new(output) if success
      return mail
    end
  end
end

input_file_name = ARGV[0]
PASSPHRASE = ARGV[1]
output_file_name = input_file_name + '-decrypted'

if File.exist?(output_file_name)
  puts "Sorry, I won't overwrite the existing file: #{output_file_name}"
  exit
end

unless File.exist?(input_file_name)
  puts "Sorry, I can't find the input file: #{input_file_name}"
  exit
end

begin
  f = File.open(output_file_name, 'w')
  new_message_found = false
  message_buffer = []
  File.open(input_file_name).each do |line|
    if line.start_with? 'From '
      Enigstore.process_message_buffer(message_buffer, f)
      message_buffer = []
      new_message_found = true
    end
    f.write(line)
    message_buffer << line
  end
  # handle the last mail (there is no closing 'From ')
  Enigstore.process_message_buffer(message_buffer, f)
ensure
  f.close
end
puts ''
puts 'DONE'
puts "Output written to: #{output_file_name}"
puts ''
