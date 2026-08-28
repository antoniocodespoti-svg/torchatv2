package com.example.torchatv2.architecture

import com.tngtech.archunit.core.importer.ClassFileImporter
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses
import org.junit.Test

class ArchitectureTest {

    private val importedClasses = ClassFileImporter().importPackages("com.example.torchatv2")

    @Test
    fun presentationShouldNotAccessCryptoDirectly() {
        noClasses().that().resideInAPackage("..presentation..")
            .should().accessClassesThat().resideInAPackage("..crypto..")
            .check(importedClasses)
    }

    @Test
    fun presentationShouldNotAccessRatchetDirectly() {
        noClasses().that().resideInAPackage("..presentation..")
            .should().accessClassesThat().resideInAPackage("..ratchet..")
            .check(importedClasses)
    }

    @Test
    fun domainShouldNotAccessAndroidFramework() {
        noClasses().that().resideInAPackage("..domain..")
            .should().accessClassesThat().resideInAPackage("android..")
            .check(importedClasses)
    }
    
    @Test
    fun cryptoShouldNotAccessTransport() {
        noClasses().that().resideInAPackage("..crypto..")
            .should().accessClassesThat().resideInAPackage("..transport..")
            .check(importedClasses)
    }
}
