pipeline {
 agent { label 'jenkins-d1' }
 environment {
        PATH = "/usr/pgsql-9.6/bin:$PATH"
    }

   stages {
      stage('Build Ruby') {
         steps {
            echo env.PATH
            sh  '''#!/bin/bash --login
                   export BUNDLE_GEMFILE=${WORKSPACE}/Gemfile
                   export PATH=$PATH

                   rm Gemfile.lock

                   rvm use 2.4.3 --install --binary --fuzzy
                   gem update --system
                   gem install bundler
                   bundle install
                   bundle exec rake 
              '''
         }
      }
     stage('Build Jruby') {
        steps {
          echo env.PATH
            sh  '''#!/bin/bash --login
                   export BUNDLE_GEMFILE=${WORKSPACE}/Gemfile
                   export PATH=$PATH

                   rm Gemfile.lock

                   rvm use jruby-9.1.17.0 --install --binary --fuzzy
                   gem update --system
                   gem install bundler
                   bundle install
                   bundle exec rake
              '''
         }
      }
   }
}

