/*
 * Copyright 2016 SimplifyOps, Inc. (http://simplifyops.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package rundeck.services

import com.dtolabs.rundeck.core.execution.ExecutionNotFound
import com.dtolabs.rundeck.core.jobs.JobExecutionError
import com.dtolabs.rundeck.core.jobs.JobService
import org.rundeck.core.executions.provenance.Provenance
import org.rundeck.core.executions.provenance.ProvenanceUtil
import spock.lang.Unroll
import com.dtolabs.rundeck.app.support.ExecutionQuery
import com.dtolabs.rundeck.core.authorization.AuthContext
import com.dtolabs.rundeck.core.authorization.SubjectAuthContext
import com.dtolabs.rundeck.core.authorization.UserAndRolesAuthContext
import com.dtolabs.rundeck.core.dispatcher.ExecutionState
import com.dtolabs.rundeck.core.execution.ExecutionReference
import com.dtolabs.rundeck.core.jobs.JobNotFound
import com.dtolabs.rundeck.core.jobs.JobReference
import grails.test.hibernate.HibernateSpec
import grails.testing.services.ServiceUnitTest
import org.rundeck.app.authorization.AppAuthContextEvaluator
import org.rundeck.core.auth.AuthConstants
import rundeck.CommandExec
import rundeck.Execution
import rundeck.ScheduledExecution
import rundeck.Workflow

/**
 * See the API for {@link grails.test.mixin.services.ServiceUnitTestMixin} for usage instructions
 */
class JobStateServiceSpec extends HibernateSpec implements ServiceUnitTest<JobStateService> {

    List<Class> getDomainClasses() { [Execution,ScheduledExecution,Workflow,CommandExec] }

    def setup() {

        service.rundeckAuthContextEvaluator=Mock(AppAuthContextEvaluator) {
            authorizeProjectJobAll(null, !null, !null, !null) >>> [true, true]
            authorizeProjectJobAny(null, !null, !null, !null) >>> [true, true]
            authorizeProjectJobAny(!null, !null, !null, !null) >>> [true, true]
            filterAuthorizedProjectExecutionsAll(null, !null, !null) >> { auth, exec, actions ->
                return exec
            }
        }
        service.frameworkService=Mock(FrameworkService){
            kickJob(!null, !null, null,!null,_,_)>>{
                Map<String, Object> ret = new HashMap<>()
                ret.success = true
                ret.executionId = '1'
                ret
            }
        }

    }

    def cleanup() {
    }
    void "job ref not found by uuid"() {
        def jobName = 'abc'
        def groupPath = null

        def projectName = 'testProj'

        def jobUuid = '123'
        def dnejobUuid = '456'
        given:
        def job = new ScheduledExecution(
                jobName: jobName,
                groupPath: groupPath,
                project: projectName,
                uuid: jobUuid,
                workflow: new Workflow(commands:[new CommandExec(adhocRemoteString: 'echo hi')])
        ).save()

        when:
        def ref = service.jobForID(null,dnejobUuid, projectName)

        then:
        JobNotFound e = thrown()
        e.jobId==dnejobUuid
        e.project==projectName
    }

    void "job ref by uuid"() {
        def jobName = 'abc'
        def groupPath = null

        def projectName = 'testProj'

        def jobUuid = '123'
        given:
            def job = new ScheduledExecution(
                    jobName: jobName,
                    groupPath: groupPath,
                    project: projectName,
                    uuid: jobUuid,
                    workflow: new Workflow(commands:[new CommandExec(adhocRemoteString: 'echo hi')])
            ).save()

        when:
        def ref = service.jobForID(null,jobUuid, projectName)

        then:
        ref!=null
        ref.id==jobUuid
        ref.jobName==jobName
        ref.groupPath==groupPath
        ref.getJobAndGroup()==jobName
    }
    void "job ref by name and group"() {
        def jobName = 'abc'
        def groupPath = 'elf'

        def projectName = 'testProj'

        def jobUuid = '123'
        given:
            def job = new ScheduledExecution(
                    jobName: jobName,
                    groupPath: groupPath,
                    project: projectName,
                    uuid: jobUuid,
                    workflow: new Workflow(commands:[new CommandExec(adhocRemoteString: 'echo hi')])
            ).save()

        when:
        def ref = service.jobForName(null,groupPath,jobName, projectName)

        then:
        ref!=null
        ref.id==jobUuid
        ref.jobName==jobName
        ref.groupPath==groupPath
        ref.getJobAndGroup()==groupPath+'/'+jobName
    }
    void "job ref by name and group not found"() {
        def jobName = 'abc'
        def groupPath = 'elf'

        def projectName = 'testProj'

        def jobUuid = '123'
        given:
            def job = new ScheduledExecution(
                    jobName: jobName,
                    groupPath: groupPath,
                    project: projectName,
                    uuid: jobUuid,
                    workflow: new Workflow(commands:[new CommandExec(adhocRemoteString: 'echo hi')])
            ).save()

        when:
        def ref = service.jobForName(null,'bogus',jobName, projectName)

        then:
        JobNotFound e = thrown()
        e.jobName==jobName
        e.groupPath=='bogus'
        e.project==projectName
    }
    void "job ref by group/name string"() {
        def jobName = 'abc'
        def groupPath = 'elf'

        def projectName = 'testProj'

        def jobUuid = '123'
        given:
            def job = new ScheduledExecution(
                    jobName: jobName,
                    groupPath: groupPath,
                    project: projectName,
                    uuid: jobUuid,
                    workflow: new Workflow(commands:[new CommandExec(adhocRemoteString: 'echo hi')])
            ).save()

        when:
        def ref = service.jobForName(null,groupPath+'/'+jobName, projectName)

        then:
        ref!=null
        ref.id==jobUuid
        ref.jobName==jobName
        ref.groupPath==groupPath
        ref.getJobAndGroup()==groupPath+'/'+jobName
    }
    void "job ref by group/name string not found"() {
        def jobName = 'abc'
        def groupPath = 'elf'

        def projectName = 'testProj'

        def jobUuid = '123'
        given:
            def job = new ScheduledExecution(
                    jobName: jobName,
                    groupPath: groupPath,
                    project: projectName,
                    uuid: jobUuid,
                    workflow: new Workflow(commands:[new CommandExec(adhocRemoteString: 'echo hi')])
            ).save()

        when:
        def ref = service.jobForName(null,'wrong/'+jobName, projectName)

        then:
        JobNotFound e = thrown()
        e.jobName==jobName
        e.groupPath=='wrong'
        e.project==projectName
    }
    void "job ref by group/name string empty group"() {
        def jobName = 'abc'
        def groupPath = null

        def projectName = 'testProj'

        def jobUuid = '123'
        given:
            def job = new ScheduledExecution(
                    jobName: jobName,
                    groupPath: groupPath,
                    project: projectName,
                    uuid: jobUuid,
                    workflow: new Workflow(commands:[new CommandExec(adhocRemoteString: 'echo hi')])
            ).save()

        when:
        def ref = service.jobForName(null,jobName, projectName)

        then:
        ref!=null
        ref.id==jobUuid
        ref.jobName==jobName
        ref.groupPath==groupPath
        ref.getJobAndGroup()==jobName
    }
    void "job state no executions"() {
        def jobName = 'abc'
        def groupPath = 'elf'

        def projectName = 'testProj'

        def jobUuid = '123'
        given:
            def job = new ScheduledExecution(
                    jobName: jobName,
                    groupPath: groupPath,
                    project: projectName,
                    uuid: jobUuid,
                    workflow: new Workflow(commands:[new CommandExec(adhocRemoteString: 'echo hi')])
            ).save()
            def reference=service.jobForID(null,jobUuid,projectName)

        when:
        def state = service.getJobState(null,reference)

        then:
        !state.running
        state.runningExecutionIds.size()==0
        state.previousExecutionState==null
    }
    void "job state single running execution"() {
        def jobName = 'abc'
        def groupPath = 'elf'

        def projectName = 'testProj'

        def jobUuid = '123'
        given:
            def job = new ScheduledExecution(
                    jobName: jobName,
                    groupPath: groupPath,
                    project: projectName,
                    uuid: jobUuid,
                    workflow: new Workflow(commands:[new CommandExec(adhocRemoteString: 'echo hi')])
            ).save()
            def exec = new Execution(
                    scheduledExecution: job,
                    dateStarted: new Date(),
                    dateCompleted: null,
                    user:'user',
                    project: projectName
            ).save()
            def reference=service.jobForID(null,jobUuid,projectName)

        when:
        def state = service.getJobState(null,reference)

        then:
        job!=null
        exec!=null
        state.running
        state.runningExecutionIds.size()==1
        state.runningExecutionIds[0]==exec.id.toString()
        state.previousExecutionState==null
    }
    void "job state multiple running executions"() {
        def jobName = 'abc'
        def groupPath = 'elf'

        def projectName = 'testProj'

        def jobUuid = '123'
        given:
            def job = new ScheduledExecution(
                    jobName: jobName,
                    groupPath: groupPath,
                    project: projectName,
                    uuid: jobUuid,
                    workflow: new Workflow(commands:[new CommandExec(adhocRemoteString: 'echo hi')])
            ).save()
            def exec = new Execution(
                    scheduledExecution: job,
                    dateStarted: new Date(),
                    dateCompleted: null,
                    user:'user',
                    project: projectName
            ).save()
            def exec2 = new Execution(
                    scheduledExecution: job,
                    dateStarted: new Date(),
                    dateCompleted: null,
                    user:'user2',
                    project: projectName
            ).save()
            def reference=service.jobForID(null,jobUuid,projectName)

        when:
        def state = service.getJobState(null,reference)

        then:
        job!=null
        exec!=null
        state.running
        state.runningExecutionIds.size()==2
        state.runningExecutionIds==new HashSet<String>([exec.id.toString(),exec2.id.toString()])
        state.previousExecutionState==null
    }
    void "job ref not authorized"() {
        def jobName = 'abc'
        def groupPath = 'elf'

        def projectName = 'testProj'

        def jobUuid = '123'
        given:


            def job = new ScheduledExecution(
                    jobName: jobName,
                    groupPath: groupPath,
                    project: projectName,
                    uuid: jobUuid,
                    workflow: new Workflow(commands:[new CommandExec(adhocRemoteString: 'echo hi')])
            ).save()
            def exec = new Execution(
                    scheduledExecution: job,
                    dateStarted: new Date(),
                    dateCompleted: null,
                    user:'user',
                    project: projectName
            ).save()

        service.frameworkService=Mock(FrameworkService){
            0 * _(*_)
        }
        service.rundeckAuthContextEvaluator=Mock(AppAuthContextEvaluator){
            1 * authorizeProjectJobAny(null,job,[AuthConstants.ACTION_READ, AuthConstants.ACTION_VIEW],projectName) >> false
        }

        when:
        def reference=service.jobForID(null,jobUuid,projectName)

        then:
        JobNotFound e = thrown()
        e.jobId==jobUuid
    }
    void "job state not authorized"() {
        def jobName = 'abc'
        def groupPath = 'elf'

        def projectName = 'testProj'

        def jobUuid = '123'
        given:


            def job = new ScheduledExecution(
                    jobName: jobName,
                    groupPath: groupPath,
                    project: projectName,
                    uuid: jobUuid,
                    workflow: new Workflow(commands:[new CommandExec(adhocRemoteString: 'echo hi')])
            ).save()
            def exec = new Execution(
                    scheduledExecution: job,
                    dateStarted: new Date(),
                    dateCompleted: null,
                    user:'user',
                    project: projectName
            ).save()

        service.frameworkService=Mock(FrameworkService){
            0 * _(*_)
        }
        service.rundeckAuthContextEvaluator=Mock(AppAuthContextEvaluator){
            authorizeProjectJobAny(null,job,[AuthConstants.ACTION_READ,AuthConstants.ACTION_VIEW],projectName) >>> [true,false]
        }

        when:
        def reference=service.jobForID(null,jobUuid,projectName)
        def state = service.getJobState(null,reference)

        then:
        JobNotFound e = thrown()
        e.jobId==jobUuid
    }
    void "job state completed state"(String status, boolean cancelled, boolean timedOut, boolean retried, ExecutionState result) {
        def jobName = 'abc'
        def groupPath = 'elf'

        def projectName = 'testProj'

        def jobUuid = '123'
        given:
            def job = new ScheduledExecution(
                    jobName: jobName,
                    groupPath: groupPath,
                    project: projectName,
                    uuid: jobUuid,
                    workflow: new Workflow(commands:[new CommandExec(adhocRemoteString: 'echo hi')])
            ).save()
            def exec = new Execution(
                    scheduledExecution: job,
                    dateStarted: new Date(),
                    dateCompleted: new Date(),
                    user:'user',
                    project: projectName,
                    status: status,
                    cancelled: cancelled,
                    abortedby: null,
                    timedOut: timedOut,
                    willRetry: retried,
            ).save()
            def reference=service.jobForID(null,jobUuid,projectName)

        def state = service.getJobState(null,reference)

        expect:
        job!=null
        exec!=null
        !state.running
        state.runningExecutionIds.size()==0
        state.previousExecutionState==result

        where:
        status | cancelled | timedOut | retried | result
        'true' | false | false | false | ExecutionState.succeeded
        'false' | false | false | false | ExecutionState.failed
        'false' | true | false | false | ExecutionState.aborted
        'false' | false | true | false | ExecutionState.timedout
        'false' | false | false | true | ExecutionState.failed_with_retry
    }

    void "start job"(){
        def jobUuid = 'c46e20a9-8555-4f15-acad-e5adba88906d'
        def projectName = 'testProj'
        JobReference job = new JobReferenceImpl()
        job.project=projectName
        job.id=jobUuid
        def auth = new SubjectAuthContext(null,null)
        given:
        Execution e1=setTestExecutions(projectName,jobUuid)
        service.frameworkService=Stub(FrameworkService){
            authorizeProjectJobAll(null,!null,!null,!null) >>> [true,true]
            authorizeProjectJobAny(null,!null,!null,!null) >>> [true,true]
            authorizeProjectJobAny(!null,!null,!null,!null) >>> [true,true]
            filterAuthorizedProjectExecutionsAll(null,!null,!null)>>{auth2, exec,actions->
                return exec
            }
            kickJob(!null, !null, null,!null,_,_)>>{
                Map<String, Object> ret = new HashMap<>()
                ret.success = true
                ret.executionId = e1.id.toString()
                ret.execution=e1
                ret
            }
        }
        when:
            def ref = service.runJob(auth, Mock(JobService.RunJob){
                getJobReference()>>job
                getExecutionType()>>'user'
                getProvenance()>>[
                    ProvenanceUtil.generic(test:'value')
                ]
            })
        then:
        ref
            ref.id == e1.id.toString()
            ref.job
            ref.job.id == jobUuid
    }

    @Unroll
    void "start job with provenance"() {
        def jobUuid = 'c46e20a9-8555-4f15-acad-e5adba88906d'
        def projectName = 'testProj'
        JobReference job = new JobReferenceImpl()
        job.project = projectName
        job.id = jobUuid
        def auth = new SubjectAuthContext(null, null)

        service.frameworkService = Stub(FrameworkService) {
            kickJob(!null, !null, null, _, expectedExecType, provenance) >> {
                Map<String, Object> ret = new HashMap<>()
                ret.success = true
                ret.executionId = '1'
                ret.execution = [
                    asReference: {
                        Mock(ExecutionReference){
                            getId()>>'1'
                            getJob()>>Mock(JobReference){
                                getId()>>jobUuid
                            }
                        }
                    }
                ]
                ret
            }
        }
        given:
            setTestExecutions(projectName, jobUuid)

        when:
            def ref = service.runJob(auth, Mock(JobService.RunJob) {
                getJobReference() >> job
                getExecutionType() >> execType
                getProvenance() >> provenance
            })
        then:
            ref
            ref.id == '1'
            ref.job
            ref.job.id == jobUuid
        where:
            execType | provenance                              | expectedExecType
            'user'   | [ProvenanceUtil.generic(source: 'xyz')] | 'user'
            'xyz'    | [ProvenanceUtil.generic(source: 'xyz')] | 'xyz'
    }
    @Unroll
    void "start job missing executionType or provenance"() {
        def jobUuid = 'c46e20a9-8555-4f15-acad-e5adba88906d'
        def projectName = 'testProj'
        JobReference job = new JobReferenceImpl()
        job.project = projectName
        job.id = jobUuid
        def auth = new SubjectAuthContext(null, null)

        service.frameworkService = Stub(FrameworkService)
        given:
            setTestExecutions(projectName, jobUuid)

        when:
            def ref = service.runJob(auth, Mock(JobService.RunJob) {
                getJobReference() >> job
                getExecutionType() >> execType
                getProvenance() >> provenance
            })
        then:
            JobExecutionError e = thrown()
            e.message.contains(expectedError+' is required')
        where:
            execType | provenance                              | expectedError
            null     | [ProvenanceUtil.generic(source: 'xyz')] | 'executionType'
            null     | null                                    | 'executionType'
            'user'     | null                                    | 'Provenance'
            'user'     | []                                    | 'Provenance'
    }

    void "start job without auth"(){
        def jobUuid = 'c46e20a9-8555-4f15-acad-e5adba88906d'
        def projectName = 'testProj'
        JobReference job = new JobReferenceImpl()
        job.project=projectName
        job.id=jobUuid
        service.frameworkService=Mock(FrameworkService){
        }

        service.rundeckAuthContextEvaluator=Mock(AppAuthContextEvaluator){
            authorizeProjectJobAny(null,!null,!null,!null) >>> [false,false]
        }
        given:
        setTestExecutions(projectName,jobUuid)

        when:
            def ref = service.runJob(null,Mock(JobService.RunJob){
                getJobReference()>>job
                getExecutionType()>>'user'
                getProvenance()>>[
                    ProvenanceUtil.generic(test:'value')
                ]
            })
        then:
        !ref
        JobNotFound ex = thrown()
    }


    def "queryExecutions simple params"() {
        setup:
        def auth = Mock(AuthContext)
        service.frameworkService = Mock(FrameworkService)
        def mockExec = Mock(Execution)
        when:
        def result = service.queryExecutions(auth, filter)
        then:
        result
        result.total == expTotal
        1 * service.frameworkService.queryExecutions(_, 0, 0) >> {ExecutionQuery query,offset,max ->
            if(query.adhoc){
                return [result: [mockExec], total: 1]
            }
            if(query.jobIdListFilter){
                return [result: [mockExec,mockExec], total: 2]
            }
            [result: [], total: 0]
        }
        1 * service.rundeckAuthContextEvaluator.filterAuthorizedProjectExecutionsAll(_, _, [AuthConstants.ACTION_READ]) >>
                {authcontext, inputArr, actions ->
            return inputArr
        }
        where:
        filter      | expTotal
        [:]                     | 0
        [adhoc:true]            | 1
        [jobonly:true]          | 0
        [jobIdListFilter:'1,2'] | 2
    }


    def setTestExecutions(projectName, jobUuid){
        def now = new Date()
        def hourInMillis = 3600*1000
        def dayInMillis = 24*hourInMillis
        def dateStarted = new Date(now.time-hourInMillis)
        def dateStartedB = new Date(now.time-dayInMillis)

        def se = new ScheduledExecution(
                jobName: 'abc',
                groupPath: null,
                project: projectName,
                uuid: jobUuid,
                workflow: new Workflow(commands:[new CommandExec(adhocRemoteString: 'echo hi')])
        ).save()
        Execution e = new Execution(argString: "-test args", user: "testuser", project: projectName, loglevel: 'WARN',
                doNodedispatch: false, scheduledExecution: se, status: 'incomplete', dateStarted: dateStarted, id:1)
        assert null!=(e.save())
        def seB = new ScheduledExecution(
                jobName: 'def',
                groupPath: 'grp',
                project: projectName,
                uuid: '2ad3f137-e005-40b8-8bb9-88e369dda798',
                workflow: new Workflow(commands:[new CommandExec(adhocRemoteString: 'echo hi')])
        ).save()
        Execution eB = new Execution(argString: "-test args", user: "testuser", project: projectName, loglevel: 'WARN',
                doNodedispatch: false, scheduledExecution: seB, status: 'incomplete', dateStarted: dateStartedB, id:2)
        assert null!=(eB.save())
        return e
    }

    def "run job with meta should pass metadata input to create job"() {
        given:
            def jobUuid = 'c46e20a9-8555-4f15-acad-e5adba88906d'
            def projectName = 'testProj'
            def opts = [:]
            def auth = Mock(UserAndRolesAuthContext)
            def ref = Mock(JobReference) {
                getProject() >> projectName
                getId() >> jobUuid
            }
            def meta = [asdf: 'asdf']
            service.frameworkService = Mock(FrameworkService)
            def job = new ScheduledExecution(
                    jobName: 'ajob',
                    groupPath: 'blah/blee',
                    project: projectName,
                    uuid: jobUuid,
                    workflow: new Workflow(commands: [new CommandExec(adhocRemoteString: 'echo hi')])
            ).save()
            def execRef = Mock(ExecutionReference)

        when:
            def result = service.runJob(auth, Mock(JobService.RunJob){
                getJobReference()>>ref
                getOptionData()>>opts
                getExtraMeta()>>meta
                getExecutionType()>>'user'
                getProvenance()>>[
                    ProvenanceUtil.generic(test:'value')
                ]
            })
        then:
            1 * service.rundeckAuthContextEvaluator.authorizeProjectJobAny(auth, job, _, projectName) >> true
            1 * service.frameworkService.kickJob(
                    job, auth, _, {
                it['meta'] == meta
            },
                'user',
                _
            ) >> [
                    success  : true,
                    execution: [asReference: { ->
                        execRef
                    }]
            ]
            result == execRef

    }

    def "execution for id with job ok"() {
        given:
            def project = 'test'
            def e=setTestExecutions(project,'test-uuid')
            def id = e.id.toString()
            def auth = Mock(UserAndRolesAuthContext)
            service.rundeckAuthContextEvaluator=Mock(AppAuthContextEvaluator)
        when:
            def result = service.executionForId(auth, id, project)
        then:
            result != null
            result.id == id
            1 * service.rundeckAuthContextEvaluator.authorizeProjectJobAny(auth, _, ['read', 'view'], project) >> true
    }
    def "execution for id with job unauthorized"() {
        given:
            def project = 'test'
            def e=setTestExecutions(project,'test-uuid')
            def id = e.id.toString()
            def auth = Mock(UserAndRolesAuthContext)
            service.rundeckAuthContextEvaluator=Mock(AppAuthContextEvaluator)
        when:
            def result = service.executionForId(auth, id, project)
        then:
            ExecutionNotFound exc = thrown()
            1 * service.rundeckAuthContextEvaluator.authorizeProjectJobAny(auth, _, ['read', 'view'], project) >> false
    }
    def "execution for id with job not found"() {
        given:
            def project = 'test'
            def id = '11'
            def auth = Mock(UserAndRolesAuthContext)
            service.rundeckAuthContextEvaluator=Mock(AppAuthContextEvaluator)
        when:
            def result = service.executionForId(auth, id, project)
        then:
            ExecutionNotFound e = thrown()
    }
    def "execution for id adhoc ok"() {
        given:
            def project = 'test'
            def e=setTestExecutions(project,'test-uuid')
            e.scheduledExecution=null
            e.save()
            def id = e.id.toString()
            def auth = Mock(UserAndRolesAuthContext)
            service.rundeckAuthContextEvaluator=Mock(AppAuthContextEvaluator)
        when:
            def result = service.executionForId(auth, id, project)
        then:
            result != null
            result.id == id
            1 * service.rundeckAuthContextEvaluator.authorizeProjectResourceAll(auth, AuthConstants.RESOURCE_ADHOC, ['read'], project) >> true
    }
    def "execution for id adhoc unauthorized"() {
        given:
            def project = 'test'
            def e=setTestExecutions(project,'test-uuid')
            e.scheduledExecution=null
            e.save()
            def id = e.id.toString()
            def auth = Mock(UserAndRolesAuthContext)
            service.rundeckAuthContextEvaluator=Mock(AppAuthContextEvaluator)
        when:
            def result = service.executionForId(auth, id, project)
        then:
            ExecutionNotFound exc = thrown()
            1 * service.rundeckAuthContextEvaluator.authorizeProjectResourceAll(auth, AuthConstants.RESOURCE_ADHOC, ['read'], project) >> false
    }
    def "provenance for execution id"() {
        given:
            def project = 'test'
            def provList=[
                ProvenanceUtil.generic(a:'b')
            ]
            def e=setTestExecutions(project,'test-uuid')
            def id = e.id.toString()
            def auth = Mock(UserAndRolesAuthContext)
            service.rundeckAuthContextEvaluator=Mock(AppAuthContextEvaluator)
            service.executionProvenanceService=Mock(ExecutionProvenanceService)
        when:
            def result = service.getExecutionProvenance(auth, id, project)
        then:
            result==provList
            1 * service.rundeckAuthContextEvaluator.authorizeProjectJobAny(auth, _, ['read', 'view'], project) >> true
            1 * service.executionProvenanceService.getProvenanceForExecution(e)>>provList
    }

}
